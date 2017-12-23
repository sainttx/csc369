#include <stdio.h>

#include "ext2.h"
#include "ext2_utils.h"

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <image file name> <path>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    ext2_init(argv[1]);

    // Create the directory inode. If the function returns a negative
    // value we have an error, and so we return it - otherwise success.
    int ino = create_inode(argv[2], MODE_C_DIR, NULL);
    return ino < 0 ? -ino : EXIT_SUCCESS;
}
