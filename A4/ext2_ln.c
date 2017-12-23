#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ext2.h"
#include "ext2_utils.h"

int main(int argc, char **argv) {
    if (argc < 4 || argc > 5
        || (argc == 5 && strcmp(argv[3], "-s") != 0)) {
        fprintf(stderr, "Usage: %s <image file name> <target> [-s] <link name>\n", argv[0]);
        exit(1);
    }

    ext2_init(argv[1]);

    // Find the target inode that we want to link to
    int target = find_inode(argv[2]);
    if (target < 0) {
        return -target;
    }

    // Check if we are creating a symbolic link or a hardlink,
    // setting the creation mode properly and passing in the
    // required arguments to create_inode.
    int sym = argc == 5;
    int err = sym ? create_inode(argv[4], MODE_C_SYMLINK, argv[2])
                  : create_inode(argv[3], MODE_C_HLINK, &target);

    // A negative value from create_inode indicates error, otherwise
    // we return successfully.
    return err < 0 ? -err : EXIT_SUCCESS;
}
