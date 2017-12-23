#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "ext2.h"

unsigned char *disk;

void print_bitmap(char *bitmap, int amount) {
    for (int byte = 0 ; byte < amount ; byte++) {
        for (int bit = 0 ; bit < 8 ; bit++) {
            int in_use = bitmap[byte] & (1 << bit);
            printf(in_use ? "1" : "0");
        }
        printf(" ");
    }
    printf("\n");
}

char get_inode_type(struct ext2_inode *inode) {
    if (inode->i_mode & EXT2_S_IFREG) {
        return 'f';
    } else if (inode->i_mode & EXT2_S_IFDIR) {
        return 'd';
    } else if (inode->i_mode & EXT2_S_IFLNK) {
        return 'l';
    }

    return -1;

}

void print_inode(struct ext2_inode* inode_table, int i_id) {
    struct ext2_inode *inode = &inode_table[i_id - 1];
    printf("[%d] type: %c size: %d links: %d blocks: %d\n", i_id,
        get_inode_type(inode), inode->i_size, inode->i_links_count, inode->i_blocks);
    printf("[%d] Blocks: ", i_id);
    for (int i = 0 ; i < inode->i_blocks / 2 ; i++) {
        printf(" %d", inode->i_block[i]);
    }
    printf("\n");
}

char get_dir_type(unsigned char type) {
    switch (type) {
        case EXT2_FT_REG_FILE: return 'f';
        case EXT2_FT_DIR: return 'd';
        case EXT2_FT_SYMLINK: return 'l';
        default: return -1;
    }
}

void print_inode_directory(struct ext2_inode* inode_table, int i_id) {
    struct ext2_inode *inode = &inode_table[i_id - 1];

    for (int j = 0 ; j < inode->i_blocks / 2 ; j++) {
        int i_block = inode->i_block[j];
        printf("    DIR BLOCK NUM: %d (for inode %d)\n", inode->i_block[j], i_id);

        int curr_len = 0;

        while (curr_len < EXT2_BLOCK_SIZE) {
            struct ext2_dir_entry *entry = (struct ext2_dir_entry *) (disk + EXT2_BLOCK_SIZE * i_block + curr_len);
            printf("Inode: %d rec_len: %d name_len: %d type= %c name=%.*s\n",
                i_id, entry->rec_len, entry->name_len, get_dir_type(entry->file_type), entry->name_len, entry->name);
            curr_len += entry->rec_len;
        }
    }


}

int main(int argc, char **argv) {

    if(argc != 2) {
        fprintf(stderr, "Usage: %s <image file name>\n", argv[0]);
        exit(1);
    }
    int fd = open(argv[1], O_RDWR);

    disk = mmap(NULL, 128 * 1024, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(disk == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    struct ext2_super_block *sb = (struct ext2_super_block *)(disk + EXT2_BLOCK_SIZE);
    printf("Inodes: %d\n", sb->s_inodes_count);
    printf("Blocks: %d\n", sb->s_blocks_count);

    struct ext2_group_desc *gd = (struct ext2_group_desc *)(disk + (EXT2_BLOCK_SIZE * 2));
    printf("Block group:\n");
    printf("    block bitmap: %d\n", gd->bg_block_bitmap);
    printf("    inode bitmap: %d\n", gd->bg_inode_bitmap);
    printf("    inode table: %d\n", gd->bg_inode_table);
    printf("    free blocks: %d\n", gd->bg_free_blocks_count);
    printf("    free inodes: %d\n", gd->bg_free_inodes_count);
    printf("    used_dirs: %d\n", gd->bg_used_dirs_count);

    unsigned char *block_bitmap = (char *)(disk + (EXT2_BLOCK_SIZE * gd->bg_block_bitmap));
    printf("Block bitmap: ");
    print_bitmap(block_bitmap, sb->s_blocks_count / 8);

    unsigned char *inode_bitmap = (char *)(disk + (EXT2_BLOCK_SIZE * gd->bg_inode_bitmap));
    printf("Inode bitmap: ");
    print_bitmap(inode_bitmap, sb->s_inodes_count / 8);

    printf("\n");
    printf("Inodes:\n");
    struct ext2_inode *inode_table = (struct ext2_inode *) (disk + EXT2_BLOCK_SIZE * gd->bg_inode_table);

    print_inode(inode_table, EXT2_ROOT_INO); // Print the root inode

    // Print any inodes that are active
    for (int i = sb->s_first_ino ; i < sb->s_inodes_count ; i++) {
        int i_byte = i / 8;
        int i_byte_index = i - (8 * i_byte);

        // Check inode_bitmap to see if inode is in use
        if (inode_bitmap[i_byte] & (1 << i_byte_index)) {
            //printf("i_byte: %d i_byte_index: %d\n", i_byte, i_byte_index);
            print_inode(inode_table, i + 1);
        }
    }

    // Go through all directories
    printf("\n");
    printf("Directory Blocks:\n");
    print_inode_directory(inode_table, EXT2_ROOT_INO); // Print the root inode directory
    for (int i = sb->s_first_ino ; i < sb->s_inodes_count ; i++) {
        int i_byte = i / 8;
        int i_byte_index = i - (8 * i_byte);

        // Check inode_bitmap to see if inode is in use
        if (inode_bitmap[i_byte] & (1 << i_byte_index)) {
            struct ext2_inode *inode = &inode_table[i];

            // Only want to handle directories
            if (get_inode_type(inode) == 'd') {
                print_inode_directory(inode_table, i + 1);
            }
        }
    }

    return 0;
}
