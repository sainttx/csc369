#include <stdio.h>

#include "ext2.h"
#include "ext2_utils.h"

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <image file name> <path>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    ext2_init(argv[1]);

    // Remove the inode at the specified path, returning the error
    // or success code.
    int ino = remove_inode(argv[2]);
    return ino < 0 ? -ino : EXIT_SUCCESS;
}
