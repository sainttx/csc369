#ifndef CSC369_EXT2_CHECKER_H
#define CSC369_EXT2_CHECKER_H

/* Defined because there is a circular dependency between the two
 * and want to fix implicit declaration warnings */

int fix_inode(int ino);

int check_directory(int ino, unsigned char * block);

#endif
