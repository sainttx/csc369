#include <stdio.h>
#include <string.h>

#include "ext2.h"
#include "ext2_utils.h"
#include "ext2_checker.h"

static unsigned char *inode_bitmap;
static unsigned char *block_bitmap;

static int get_free_bits(unsigned char *bitmap, int size) {
    int count = 0;
    for (int byte = 0 ; byte < size ; byte++) {
        for (int bit = 0 ; bit < 8 ; bit++) {
            int in_use = bitmap[byte] & (1 << bit);
            if (!in_use) {
                count++;
            }
        }
    }
    return count;
}

static int fix_count_sb(int wanted, unsigned int *target) {
    if (*target != wanted) {
        int diff = *target - wanted;
        *target = wanted;
        return diff < 0 ? -diff : diff; // Absolute value
    }
    return 0;
}

static int fix_count_gd(int wanted, short unsigned int *target) {
    if (*target != wanted) {
        int diff = *target - wanted;
        *target = wanted;
        return abs(diff);
    }
    return 0;
}

static int is_set(unsigned char *bitmap, int bit) {
    unsigned char *byte = bitmap + (bit / 8);
    return *byte & (1 << (bit % 8));
}

// Fix unallocated blocks for inode in the bitmap
static int fix_blocks(struct ext2_inode *inode) {
    int fixed_blocks = 0;
    for (int i = 0 ; i < 15 ; i++) {
        if (inode->i_block[i] == 0) {
            continue;
        }

        if (i < 12) {
            if (!is_set(block_bitmap, inode->i_block[i] - 1)) {
                claim_block(inode->i_block[i] - 1);
                fixed_blocks += 1;
            }
        } else {
            unsigned int *iblock = (unsigned int *) get_block(inode->i_block[i]);
            for (int j = 0 ; j < PTRS_PER_INDIRECT_BLOCK ; j++) {
                if (iblock[j] != 0 && !is_set(block_bitmap, iblock[j] - 1)) {
                    claim_block(iblock[j] - 1);
                    fixed_blocks += 1;
                }
            }
        }
    }
    return fixed_blocks;
}

int is_dot_dir(char *name, int len) {
    return strncmp(name, "..", len) == 0;
}

int check_directory(int ino, unsigned char * block) {
    int fixed = 0;
    int len = 0;

    while (len < EXT2_BLOCK_SIZE) {
        struct ext2_dir_entry *curr = (struct ext2_dir_entry *)(block + len);

        if (curr->rec_len == 0 || curr->rec_len == EXT2_BLOCK_SIZE) {
            break;
        }

        struct ext2_inode *inode = get_inode(curr->inode);

        // Check i_mode vs file_type
        if (inode->i_mode & EXT2_S_IFREG) {
            if (curr->file_type != EXT2_FT_REG_FILE) {
                curr->file_type = EXT2_FT_REG_FILE;
                fixed += 1;
                printf("Fixed: Entry type vs inode mismatch: inode [%d]\n", curr->inode);
            }
        } else if (inode->i_mode & EXT2_S_IFDIR) {
            if (curr->file_type != EXT2_FT_DIR) {
                curr->file_type = EXT2_FT_DIR;
                fixed += 1;
                printf("Fixed: Entry type vs inode mismatch: inode [%d]\n", curr->inode);
            }
        } else if (inode->i_mode & EXT2_S_IFLNK) {
            if (curr->file_type != EXT2_FT_SYMLINK) {
                curr->file_type = EXT2_FT_SYMLINK;
                fixed += 1;
                printf("Fixed: Entry type vs inode mismatch: inode [%d]\n", curr->inode);
            }
        }

        // if inode is not the '.' or '..' entries we recursively it
        if (!is_dot_dir(curr->name, curr->name_len)) {
            fixed += fix_inode(curr->inode);
        }

        len += curr->rec_len;
    }

    return fixed;
}


int fix_inode(int ino) {
    struct ext2_inode *inode = get_inode(ino);

    int fixes = 0;

    // Reset the dtime of a valid inode if marked
    if (inode->i_dtime != 0) {
        printf("Fixed: valid inode marked for deletion: [%d]\n", ino);
        inode->i_dtime = 0;
        fixes += 1;
    }

    // Fix inode not being allocated in inode bitmap
    if (!is_set(inode_bitmap, ino - 1)) {
        claim_inode(ino -1);
        fixes += 1;
        printf("Fixed: inode [%d] not marked as in-use\n", ino);
    }

    // Fix any blocks not being allocated in block bitmap
    int fixed_blocks = fix_blocks(inode);
    if (fixed_blocks > 0) {
        printf("Fixed: %d in-use data blocks not marked in data bitmap for inode: [%d]\n", fixed_blocks, ino);
        fixes += fixed_blocks;
    }

    // If the inode is a directory, go into the directory block structure
    // and check the entries against their inodes. If a found inode is a directory
    // we must recursively traverse to fix any nested issues.
    if (inode->i_mode & EXT2_S_IFDIR) {
        for (int i = 0 ; i < 15 ; i++) {
            if (inode->i_block[i] == 0) {
                continue;
            }

            if (i < 12) {
                fixes += check_directory(ino, get_block(inode->i_block[i]));
            } else {
                unsigned int *iblock = (unsigned int *) get_block(inode->i_block[i]);
                for (int j = 0 ; j < PTRS_PER_INDIRECT_BLOCK ; j++) {
                    if (iblock[j] != 0) {
                        fixes += check_directory(ino, get_block(iblock[j]));
                    }
                }
            }
        }
    }

    return fixes;
}


int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <image file name>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    ext2_init(argv[1]);
    inode_bitmap = (unsigned char *)(disk + (EXT2_BLOCK_SIZE * gd->bg_inode_bitmap));
    block_bitmap = (unsigned char *)(disk + (EXT2_BLOCK_SIZE * gd->bg_block_bitmap));

    int total_fixed = 0;

    int free_inodes = get_free_bits(inode_bitmap, sb->s_inodes_count / 8);
    int free_blocks = get_free_bits(block_bitmap, sb->s_blocks_count / 8);

    int fixed;

    if ((fixed = fix_count_sb(free_inodes, &sb->s_free_inodes_count)) > 0) {
        printf("Fixed: superblock's free inodes counter was off by %d compared to bitmap\n", fixed);
        total_fixed += fixed;
    }

    if ((fixed = fix_count_sb(free_blocks, &sb->s_free_blocks_count)) > 0) {
        printf("Fixed: superblock's free blocks counter was off by %d compared to bitmap\n", fixed);
        total_fixed += fixed;
    }

    if ((fixed = fix_count_gd(free_inodes, &gd->bg_free_inodes_count)) > 0) {
        printf("Fixed: block group's free inodes counter was off by %d compared to bitmap\n", fixed);
        total_fixed += fixed;
    }

    if ((fixed = fix_count_gd(free_blocks, &gd->bg_free_blocks_count)) > 0) {
        printf("Fixed: block group's free inodes counter was off by %d compared to bitmap\n", fixed);
        total_fixed += fixed;
    }

    total_fixed += fix_inode(EXT2_ROOT_INO);

    if (total_fixed == 0) {
        printf("No file system inconsistencies repaired!\n");
    } else {
        printf("%d file system inconsistencies repaired!\n", total_fixed);
    }

    return EXIT_SUCCESS;
}
