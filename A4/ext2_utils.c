#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <time.h>

#include "ext2.h"
#include "ext2_utils.h"

#define MAX(x, y) ((x > y) ? x : y) /* Take the max of 2 values */

unsigned char *disk;
struct ext2_super_block *sb;
struct ext2_group_desc *gd;

/******************/
/** STRING UTILS **/
/******************/

/**
 * Returns whether a string is referencing an absolute path.
 */
static int is_absolute_path(const char *path) {
    return strncmp(path, "/", 1) == 0;
}

/**
 * Returns the index inside the string at which trailing slashes
 * begin.
 */
static int get_trailing_slash(char *s) {
    int i = 0;
    int index = -1;
    while (s[i] != '\0') {
        if (s[i] != '/') {
            index = i;
        }
        i++;
    }
    return index;
}

/**
 * Extracts the file name and parent folder path from a valid absolute path.
 *
 * This method takes a string path and extracts the file name from the path
 * name, assigning the values to their respective destinations. Passing in a
 * NULL value for either destination will ignore the assignment.
 *
 * Example:
 * split_file_name(f, p, "/folder/file") will result in:
 *  - f = "file"
 *  - p = "/folder/"
 */
void split_file_name(char **f, char**p, char *haystack) {
    int sindex = get_trailing_slash(haystack);

    // Check if we have only received forward slashes or a non-absolute path
    if (sindex == -1) {
        return;
    }

    size_t len = strlen(haystack);

    // If there are trailing slashes present, we replace our current reference
    // of haystack to a newly allocated string that has the slashes removed.
    // We allocate new memory for the string
    if (sindex != len - 1) {
        char *new_haystack = malloc(sizeof(char) * sindex + 1);
        new_haystack[sindex + 1] = '\0';
        strncpy(new_haystack, haystack, sindex + 1);
        haystack = new_haystack;
        len = strlen(haystack); // Update the new haystack length
    }

    /*
     * We now get a pointer to the last '/' in the haystack which indicates
     * the beginning of the file path. We truncate the leading '/' and assign
     * it to the file destination, and also assign path to the previous section
     * of the string.
     */
    char *fname = strrchr(haystack, '/') + 1;
    size_t flen = strlen(fname);
    size_t plen = len - flen;
    *f = malloc(sizeof(char) * flen);
    *p = malloc(sizeof(char) * plen);
    strncpy(*f, fname, flen);
    strncpy(*p, haystack, plen);

    // If there were trailing slashes, it indicates that haystack was replaced
    // by a newly allocated string -- which must be free'd.
    if (sindex != len - 1) {
        free(haystack);
    }
}


/**
 * Returns the proper rec_len size for a directory entry, aligned
 * to 4 bytes.
 */
static int get_rec_len(int name_len) {
    int padding = 4 - (name_len % 4);
    return 8 + name_len + padding;
}

/******************/
/** BITMAP UTILS **/
/******************/

/**
 * Helper method that returns the first available index in a bitmap
 *
 * [size] indicates the number of bytes that can be searched, [reserved]
 * indicating which first n bits are reserved by the file system.
 */
static int search_bitmap(unsigned char *bitmap, int size, int reserved) {
    for (int byte = 0 ; byte < size ; byte++) {
        for (int bit = 0 ; bit < 8 ; bit++) {
            int in_use = bitmap[byte] & (1 << bit);
            if (!in_use) {
                int pos = 8 * byte + bit;
                if (pos >= reserved) {
                    return pos + 1;
                }
            }
        }
    }
    return -1;
}

/**
 * Returns the number of the next inode available.
 *
 * NOTE: Not to be confused with the inode index in the bitmap
 */
static int next_inode() {
    unsigned char *inode_bitmap = (unsigned char *)(disk + (EXT2_BLOCK_SIZE * gd->bg_inode_bitmap));
    return search_bitmap(inode_bitmap, sb->s_inodes_count / 8, sb->s_first_ino);
}

/**
 * Returns the number of the next block available.
 *
 * NOTE: Not to be confused with the block index in the bitmap
 */
static int next_block() {
    unsigned char *block_bitmap = (unsigned char *)(disk + (EXT2_BLOCK_SIZE * gd->bg_block_bitmap));
    return search_bitmap(block_bitmap, sb->s_blocks_count / 8, 0);
}

/* Helper method to set the proper bit in a bitmap */
static void set_bit(unsigned char *bitmap, int bit, int val) {
    unsigned char *byte = bitmap + (bit / 8);
    if (val == 1) {
        *byte |= 1 << (bit % 8);
    } else {
        *byte &= ~(1 << (bit % 8));
    }
}

/*
 * @see ext2_utils.h
 */
void claim_inode(int bit) {
    unsigned char *inode_bitmap = (unsigned char *)(disk + (EXT2_BLOCK_SIZE * gd->bg_inode_bitmap));
    set_bit(inode_bitmap, bit, 1);
    gd->bg_free_inodes_count--;
    sb->s_free_inodes_count--;
}

/* Unclaims a bit inside the inode bitmap */
static void unclaim_inode(int bit) {
    unsigned char *inode_bitmap = (unsigned char *)(disk + (EXT2_BLOCK_SIZE * gd->bg_inode_bitmap));
    set_bit(inode_bitmap, bit, 0);
    gd->bg_free_inodes_count++;
    sb->s_free_inodes_count++;
}

/*
 * @see ext2_utils.h
 */
void claim_block(int bit) {
    unsigned char *block_bitmap = (unsigned char *)(disk + (EXT2_BLOCK_SIZE * gd->bg_block_bitmap));
    set_bit(block_bitmap, bit, 1);
    gd->bg_free_blocks_count--;
    sb->s_free_blocks_count--;
}

/* Unclaims a bit inside the block bitmap */
static void unclaim_block(int bit) {
    unsigned char *block_bitmap = (unsigned char *)(disk + (EXT2_BLOCK_SIZE * gd->bg_block_bitmap));
    set_bit(block_bitmap, bit, 0);
    gd->bg_free_blocks_count++;
    sb->s_free_blocks_count++;
}

/*
 * @see ext2_utils.h
 */
struct ext2_inode *get_inode(int ino) {
    return & ((struct ext2_inode *)
              (disk + EXT2_BLOCK_SIZE * gd->bg_inode_table))[ino-1];
}

/*
 * @see ext2_utils.h
 */
unsigned char *get_block(int blk) {
    return disk + (EXT2_BLOCK_SIZE * blk);
}

/*************************/
/** DIRECTORY SEARCHING **/
/*************************/

/* Finds the last entry in a directory */
struct ext2_dir_entry *last_entry(struct ext2_dir_entry *entry, int* fs_dest) {
    int size = 0;
    while (size < EXT2_BLOCK_SIZE) {
        int rsize = get_rec_len(entry->name_len);
        if (rsize != entry->rec_len) {
            size += rsize;
            break;
        }

        size += entry->rec_len;
        entry = (struct ext2_dir_entry *) (((unsigned char *) entry) + entry->rec_len);
    }

    if (fs_dest) {
        *fs_dest = EXT2_BLOCK_SIZE - size;
    }
    return entry;
}

/**
 * Directory search predicate definitions.
 *
 * The searching mechanism created uses function predicates when checking
 * iterated directory entries. Predicaates can return 3 values, defined below
 * which tells the searching algorithm what to do with the current entry
 * being checked in the directory.
 */
#define PRED_VALID   0 /* current entry is valid */
#define PRED_INVALID 1 /* current entry is invalid */
#define PRED_SKIP_BL 2 /* current block is invalid, skip it */

/**
 * Finds the offset at which a hidden entry is located from an entry.
 *
 * @param entry The entry to search from
 * @param name  The name of the hidden entry we are searching for
 * @param space Amount of room we have available to search
 *
 * @return Offset from entry at which the hidden entry is, or -1 if the
 *         entry was not found.
 */
static int offset_to_hidden(struct ext2_dir_entry *entry, char *name, int space) {
    int req = get_rec_len(strlen(name)); // Req. amt of space for hidden entry to fit
    struct ext2_dir_entry *curr = entry;
    int offset = 0;

    while (space > 0) {
        if (req > space || curr->rec_len == 0 || curr->name_len <= 1) {
            break; // Won't be able to find the hidden inode
        } else if (strncmp(curr->name, name, strlen(name)) == 0) {
            return offset; // Found the hidden entry
        }

        int len = get_rec_len(curr->name_len); // Get true length to increment
        space -= len;
        offset += len;
        curr = (struct ext2_dir_entry *) (((unsigned char *) curr) + len);
    }

    return -1;
}

/* Predicate function to test if an entry is hiding a removed inode */
static int test_hiding_entry(struct ext2_dir_entry *entry, void* fname) {
    int real_len = get_rec_len(entry->name_len);
    char *name = (char *) fname;
    int space = entry->rec_len - real_len;
    int offset = offset_to_hidden(entry, name, space);
    return offset > 0 ? PRED_VALID : PRED_INVALID;
}

/* Predicate function to test if an entry has a specific name */
static int test_name(struct ext2_dir_entry *entry, void* fname) {
    return (strncmp(entry->name, (char *) fname, MAX(entry->name_len, strlen((char*) fname))) == 0)
                ? PRED_VALID : PRED_INVALID;
}

/*
 * Predicate function to test if a block has enough free space to fit an entry
 * with specific length.
 */
static int test_free_space(struct ext2_dir_entry *entry, void* fname_len) {
    int req = get_rec_len(*((int*) fname_len));
    int fs = -1;
    last_entry(entry, &fs); // Populate free space
    return fs > req ? PRED_VALID : PRED_SKIP_BL;
}

/**
 * Search mode definitions.
 *
 * Tells the algorithm which entry relative to the current one
 * being searched should be returned.
 */
#define MODE_S_EXACT    0 /* the current entry */
#define MODE_S_PREV     1 /* previous entry */
#define MODE_S_BL_START 2 /* entry at start of block */

/**
 * Searches the entries inside of a block.
 *
 * Uses a predicate function to determine whether an entry is valid
 * and should be returned (according to the search mode).
 *
 * @param rmode     Search mode specific (ie. MODE_S_*)
 * @param block     Current block number being searched
 * @param predicate Predicate function to check entries
 * @param param     Extra parameters for predicate function
 *
 * @return Found entry inside the block, or NULL.
 */
static struct ext2_dir_entry *search_block(int rmode, unsigned int block,
             int (*predicate) (struct ext2_dir_entry*, void*),
             void *param) {
    int len = 0;

    struct ext2_dir_entry *prev = NULL;
    struct ext2_dir_entry *curr = NULL;

    while (len < EXT2_BLOCK_SIZE) {
        prev = curr;
        curr = (struct ext2_dir_entry *)(get_block(block) + len);

        if (curr == 0) {
            return NULL;
        }

        int pred = predicate(curr, param);

        if (pred == PRED_VALID) { // Valid entry
            switch (rmode) {
                case MODE_S_EXACT: // Return current entry
                    return curr;
                case MODE_S_PREV: // Return previous
                    return prev ? prev : curr;
                case MODE_S_BL_START:
                    return (struct ext2_dir_entry *) get_block(block);
            }
        } else if (pred == PRED_SKIP_BL) { // Skip block
            return NULL;
        }

        len += curr->rec_len;
    }

    return NULL;
}

/**
 * Searches the blocks inside a directory.
 *
 * @param rmode     Search mode specific (ie. MODE_S_*)
 * @param inode     inode being searched
 * @param predicate Predicate function to check entries
 * @param param     Extra parameters for predicate function
 *
 * @return Found entry inside the directory, or NULL.
 */
static struct ext2_dir_entry *search_directory(int rmode, struct ext2_inode *inode,
                 int (*predicate) (struct ext2_dir_entry*, void*),
                 void *param) {
    for (int i = 0 ; i < 13 ; i++) {
        if (inode->i_block[i] == 0) {
            continue;
        }

        struct ext2_dir_entry *entry;
        if (i < 12) { // Search direct block
            entry = search_block(rmode, inode->i_block[i], predicate, param);
        } else { // Get pointers to indirect block
            unsigned int *iblock = (unsigned int *) get_block(inode->i_block[i]);
            for (int j = 0 ; j < PTRS_PER_INDIRECT_BLOCK ; j++) {
                if (iblock[j] == 0) {
                    continue;
                }

                entry = search_block(rmode, iblock[j], predicate, param);
                if (entry) {
                    return entry;
                }
            }
        }

        if (entry) {
            return entry;
        }
    }

    return NULL;
}

/* Finds an inode entry with a specific name inside a directory */
static struct ext2_dir_entry *find_entry(struct ext2_inode *inode, char *fname) {
    return search_directory(MODE_S_EXACT, inode, test_name, fname);
}

/**
 * Inserts an inode into a directory.
 *
 * @param dir Directory to insert into
 * @param inode inode being inserted
 * @param fname Name of inserted inode
 * @param ftype File type of inserted inode
 *
 * @return the created directory entry for the inserted inode.
 */
 static struct ext2_dir_entry *insert_into_directory(struct ext2_inode *dir, int inode, char *fname, unsigned int ftype) {
     int len = strlen(fname);
     struct ext2_dir_entry *entry = search_directory(1, dir, test_free_space, (void *) &len); // Returned value is start of block (mode 1)

     int free_space = -1;
     entry = last_entry(entry, &free_space);

     // This case only occurs when we are inserting the first item into a block
     if (entry->rec_len < EXT2_BLOCK_SIZE) {
         int size = get_rec_len(entry->name_len);
         entry->rec_len = size; // Adjust the current last entry length to its real size
         entry = (struct ext2_dir_entry *)(((unsigned char *) entry) + size); // Move to next entry
     }

     entry->inode = inode;
     entry->rec_len = free_space;
     entry->name_len = len;
     entry->file_type = ftype;
     memcpy(entry->name, fname, len);
     return entry;
 }

/**
 * Finds a place inside an inode to insert a block.
 *
 * @param ino Inode to insert to
 * @parma blk Block number to insert
 *
 * @return 0 or error code.
 */
static int add_block_to_inode(int ino, int blk) {
    struct ext2_inode *inode = get_inode(ino);
    for (int i = 0 ; i < 13 ; i++) {
        // Direct pointer insertion is simple - just assign it
        if (i < 12) {
            if (inode->i_block[i] == 0) {
                inode->i_block[i] = blk;
                inode->i_blocks += 2;
                return 0;
            }
        } else { // Handle indirect pointer creation
            // If the indirect block hasn't been assigned yet, we create it
            // and add it to the inode.
            if (inode->i_block[i] == 0) {
                int b = next_block();
                if (b == -1) {
                    break;
                }
                inode->i_block[i] = b;
                inode->i_blocks += 2;
                claim_block(b - 1);
            }

            // With the indirect block, we must find a free slot to insert the
            // block number we want to add to the inode.
            unsigned int *iblock = (unsigned int *) get_block(inode->i_block[i]);
            for (int i = 0 ; i < PTRS_PER_INDIRECT_BLOCK ; i++) {
                if (iblock[i] == 0) {
                    iblock[i] = blk;
                    inode->i_blocks += 2;
                    return 0;
                }
            }
        }
    }
    return ENOSPC;
}

/* Helper function that finds a block to append data to an inode */
static int _write(int ino, char *data, size_t len) {
    int blk = next_block();

    if (blk == -1) {
        return ENOSPC;
    }

    unsigned char *b = get_block(blk);
    get_inode(ino)->i_size += len;
    memcpy(b, data, len);
    int err = add_block_to_inode(ino, blk);
    if (err != 0) {
        return err;
    }
    claim_block(blk - 1);
    return 0;
}

/**
 * Writes new data to an inode.
 *
 * @param ino  Inode number
 * @param data Data to write
 * @param len  Size of data
 *
 * @return 0 or error code
 */
int write_to_inode(int ino, char *data, size_t len) {
    // while len > max block size, write block and then move pointer forward
    while (len > EXT2_BLOCK_SIZE) {
        int err = _write(ino, data, len);
        if (err > 0) {
            return err;
        }
        data = data + EXT2_BLOCK_SIZE;
        len -= EXT2_BLOCK_SIZE;
    }

    return _write(ino, data, len);
}

/**
 * Initializes an EXT2 file system from a file on disk
 *
 * @param file path to file
 *
 * @return success or failure code
 */
void ext2_init(const char *file) {
  int fd = open(file, O_RDWR);

  disk = mmap(NULL, 128 * EXT2_BLOCK_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

  if(disk == MAP_FAILED) {
    perror("mmap");
    exit(EXIT_FAILURE);
  }

  sb = (struct ext2_super_block *)(disk + EXT2_BLOCK_SIZE);
  gd = (struct ext2_group_desc *)(disk + (EXT2_BLOCK_SIZE * 2));
}

/*
 * @see ext2_utils.h
 */
int create_inode(char *path, int mode, void *extra) {
    // Since there is no concept of "current working directory", we must check
    // that the user has enteres an absolute path (ie. "/f1/f2").
    if (!is_absolute_path(path)) {
        return -ENOENT;
    }

    char *f, *p;
    split_file_name(&f, &p, path);

    int parent = find_inode(p);
    if (parent < 0) { // Indicates error
        return parent;
    }
    struct ext2_inode *parent_ino = get_inode(parent);

    // Check if f already in parent
    if (find_entry(parent_ino, f) != NULL) {
        return -EEXIST;
    }

    // The creation of hard links is very straightforward - we simply just
    // insert a directory entry pointing to the target inode.
    if (mode == MODE_C_HLINK) {
        if (!extra) {
            return -1;
        }
        int t_ino = *((int *) extra);
        struct ext2_inode *target = get_inode(t_ino);
        insert_into_directory(parent_ino, t_ino, f, EXT2_FT_REG_FILE);
        target->i_links_count++;
        return t_ino;
    }

    int ino = next_inode();
    if (ino == -1) { // Check if there is a free inode
        return -ENOSPC;
    }

    struct ext2_inode *inode = get_inode(ino);
    inode->i_uid = 0;
    inode->i_size = 0;
    inode->i_blocks = 0;
    inode->i_dtime = 0;
    inode->i_ctime = time(NULL);
    for (int i = 0 ; i < 15 ; i++) { // Wipe all other blocks
        inode->i_block[i] = 0;
    }
    inode->i_gid = 0;
    inode->osd1 = 0;
    inode->i_file_acl = 0;
    inode->i_dir_acl = 0;
    inode->i_faddr = 0;
    inode->i_links_count = 1; // From parent directory

    int ft;

    if (mode == MODE_C_DIR) {
        int blk = next_block();
        if (blk == -1) {
            return -ENOSPC;
        }

        inode->i_block[0] = blk; // Set first block to our new claimed

        struct ext2_dir_entry *block = (struct ext2_dir_entry *) get_block(blk);
        block->rec_len = EXT2_BLOCK_SIZE;
        insert_into_directory(inode, ino, ".", EXT2_FT_DIR);
        insert_into_directory(inode, parent, "..", EXT2_FT_DIR);
        parent_ino->i_links_count++;
        inode->i_mode = EXT2_S_IFDIR;
        ft = EXT2_FT_DIR;
        inode->i_links_count = 2; // '.' and entry from parent inode
        inode->i_size = EXT2_BLOCK_SIZE;
        inode->i_blocks += 2;
        claim_block(blk - 1);
    } else if (mode == MODE_C_SYMLINK) {
        inode->i_mode = EXT2_S_IFLNK;
        ft = EXT2_FT_SYMLINK;
        char *data = (char *) extra;
        write_to_inode(ino, data, strlen(data));
    } else { // Regular file
        inode->i_mode = EXT2_S_IFREG;
        ft = EXT2_FT_REG_FILE;
    }

    insert_into_directory(parent_ino, ino, f, ft);
    claim_inode(ino - 1);
    return ino;
}

/* Sets or unsets an inodes blocks, depending on bitmap_func */
static void fix_blocks(int ino, void (*bitmap_func) (int)) {
    struct ext2_inode *inode = get_inode(ino);
    for (int i = 0 ; i < 13 ; i++) {
        if (inode->i_block[i] == 0) {
            continue;
        }

        if (i < 12) {
            bitmap_func(inode->i_block[i] - 1);
        } else {
            unsigned int *iblock = (unsigned int *) get_block(inode->i_block[i]);
            for (int i = 0 ; i < PTRS_PER_INDIRECT_BLOCK ; i++) {
                if (iblock[i] != 0) {
                    bitmap_func(iblock[i] - 1);
                }
            }
        }
    }
}

/*
 * @see ext2_utils.h
 */
int remove_inode(char *path) {
    if (!is_absolute_path(path)) {
        return -ENOENT;
    }

    char *f, *p;
    split_file_name(&f, &p, path);

    int parent = find_inode(p);
    if (parent < 0) { // Indicates error
        return parent;
    }

    // Get the parent inode (directory) where the target will be in
    struct ext2_inode *parent_ino = get_inode(parent);

    // Validate that the parent is actually a directory
    if (!(parent_ino->i_mode & EXT2_S_IFDIR)) {
        return -ENOTDIR;
    }

    // Search for the file inode, setting the search to return the previous inode
    // in the directory.
    struct ext2_dir_entry *prev = search_directory(MODE_S_PREV, parent_ino, test_name, f);
    if (!prev) {
        return -ENOENT;
    }

    // We can get the target inode by moving the offset by rec_len
    struct ext2_dir_entry *del = (struct ext2_dir_entry *) (((unsigned char *) prev) + prev->rec_len);

    // Don't allow deletion of directories
    if (del->file_type == EXT2_FT_DIR) {
        return -EISDIR;
    }

    // Update the deletion time of our inode, unclaim the blocks and inode in
    // their respective bitmaps.
    struct ext2_inode *inode = get_inode(del->inode);
    inode->i_dtime = time(NULL);
    fix_blocks(del->inode, unclaim_block);
    unclaim_inode(del->inode - 1);

    // Set the previous inodes length to cover over our inode
    prev->rec_len += del->rec_len;
    return del->inode;
}

/*
 * @see ext2_utils.h
 */
int restore_inode(char *path) {
    if (!is_absolute_path(path)) {
        return -ENOENT;
    }

    char *f, *p;
    split_file_name(&f, &p, path);

    int parent = find_inode(p);
    if (parent < 0) { // Indicates error
        return parent;
    }
    struct ext2_inode *parent_ino = get_inode(parent);

    // Check if the parent is a directory
    if (!(parent_ino->i_mode & EXT2_S_IFDIR)) {
        return -ENOTDIR;
    }

    struct ext2_dir_entry *hiding = search_directory(MODE_S_EXACT, parent_ino, test_hiding_entry, f);

    if (!hiding) {
        return -ENOENT;
    }

    /* If there is any extra "padding" (ie. the hiding entry is taking up the
       remaining space in the block), we must make sure the restored entry takes
       up that space, so we add it on top of its rec_len */
    int real_len = get_rec_len(hiding->name_len);
    int extra = hiding->rec_len - real_len;
    int len = offset_to_hidden(hiding, f, extra);
    extra = hiding->rec_len - len;

    struct ext2_dir_entry *hidden = (struct ext2_dir_entry *) (((unsigned char *) hiding) + len);

    // Set the rec_len to its real amount and add any padding on to it
    int padding = extra - hidden->rec_len;
    hidden->rec_len = get_rec_len(hidden->name_len);
    if (padding > 0) {
        hidden->rec_len += padding;
    }

    // Set the rec_len of the hiding entry to its proper amount
    hiding->rec_len = len;

    /* Update the deletion time and restore the inodes blocks/inode in bitmaps */
    struct ext2_inode *inode = get_inode(hidden->inode);
    inode->i_dtime = 0;
    fix_blocks(hidden->inode, claim_block);
    claim_inode(hidden->inode - 1);
    return hidden->inode;
}

/*
 * @see ext2_utils.h
 */
int find_inode(char *path) {
    int ino = EXT2_ROOT_INO;
    struct ext2_inode *inode = get_inode(ino);
    char *t = strtok(path, "/");

    while (t) {
        // Check if the found inode is a directory
        if (!(inode->i_mode & EXT2_S_IFDIR)) {
            return -ENOTDIR;
        }

        struct ext2_dir_entry *d = find_entry(inode, t);

        if (!d) {
            return -ENOENT;
        }

        ino = d->inode;
        inode = get_inode(ino);
        t = strtok(NULL, "/");
    }

    return ino;
}
