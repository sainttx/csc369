#include <stdio.h>

#include "ext2.h"
#include "ext2_utils.h"

/**
 * Copies the contents of a file on the native operating system into an
 * inode on the EXT2 file system.
 */
static int copy_file_to_inode(char *file, int ino) {
    FILE *fp = fopen(file, "r");

    if (!fp) {
        return ENOENT;
    }

    // Get the size of the inode in order to check the size
    // against our drive.
    fseek(fp, 0L, SEEK_END);
    size_t fsize = ftell(fp);
    if (fsize > sb->s_free_blocks_count * EXT2_BLOCK_SIZE
        || fsize > MAX_INODE_SIZE) {
        fclose(fp);
        return ENOSPC;
    }

    // Reset the file pointer to the first index, prepare for reading
    char buffer[EXT2_BLOCK_SIZE + 1];
    buffer[EXT2_BLOCK_SIZE] = '\0';
    fseek(fp, 0L, SEEK_SET);
    size_t read;

    // Read in 1K (or what EXT2_BLOCK_SIZE is set to) at a time, writing the
    // new data to the inode.
    while ((read = fread(buffer, 1, EXT2_BLOCK_SIZE, fp)) == EXT2_BLOCK_SIZE) {
        int err = write_to_inode(ino, buffer, read);
        if (err != 0) {
            fclose(fp);
            return err;
        }
    }

    // When we exit the while loop, we must write the remaining data
    // (< EXT2_BLOCK_SIZE) not written in the loop to our block.
    if (read > 0) {
        buffer[read] = '\0';
        int err = write_to_inode(ino, buffer, read);
        if (err != 0) {
            fclose(fp);
            return err;
        }
    }

    fclose(fp);
    return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <image file name> <native file> <path>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    ext2_init(argv[1]);

    // Create the inode. If the function returns a negative
    // value we have an error and so we return it.
    int ino = create_inode(argv[3], MODE_C_REG, NULL);
    if (ino < 0) {
        return -ino;
    }

    // Attempt to copy the native file into the inode,
    // and return the exit code from the function.
    return copy_file_to_inode(argv[2], ino);
}
