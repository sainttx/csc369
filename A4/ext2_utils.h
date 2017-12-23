
#ifndef CSC369_EXT2_UTILS_H
#define CSC369_EXT2_UTILS_H

#include <stdlib.h>
#include <errno.h>

#include "ext2.h"

/* Size of first 11 blocks + size of single indirect block */
#define MAX_INODE_SIZE ((EXT2_BLOCK_SIZE * 11) \
                        + ((EXT2_BLOCK_SIZE / sizeof(unsigned int)) \
                        * EXT2_BLOCK_SIZE))

/* Number of block pointers in an indirect block */
#define PTRS_PER_INDIRECT_BLOCK (EXT2_BLOCK_SIZE / sizeof(unsigned int))

/* The pointer to our super block */
extern unsigned char *disk;
extern struct ext2_super_block *sb;
extern struct ext2_group_desc *gd;

/**
 * Loads an EXT2 formatted file system from a path on the system.
 *
 * @param file The path to the file
 *
 * @return EXIT_FAILURE or EXIT_SUCCESS depending on whether the
 *         file system was successfully mapped to memory.
 */
void ext2_init(const char *file);

/**
 * Claims a bit inside the inode bitmap.
 *
 * @param bit The bit to claim
 */
void claim_inode(int bit);

/**
 * Claims a bit inside the block bitmap.
 *
 * @param bit The bit to claim
 */
void claim_block(int bit);

/**
 * Returns a pointer to the first entry of a block.
 *
 * @param blk Block number to retrieve. Not to be confused with block bit,
 *            which is actually 1 less than the block number.
 *
 * @return First entry of the block
 */
unsigned char *get_block(int blk);

/**
 * Returns the pointer to an inode.
 *
 * @param ino Inode id number
 *
 * @return The inode corresponding to ino.
 */
struct ext2_inode *get_inode(int ino);

/*
 * Creation modes for inode.
 */
#define    MODE_C_REG     0  /* regular inode */
#define    MODE_C_DIR     1  /* directory inode */
#define    MODE_C_HLINK   2  /* hard link to inode */
#define    MODE_C_SYMLINK 3  /* symbolic link */

/**
 * Creates a new inode at the specified path.
 *
 * The path must be an absolute path, containing a valid location up
 * to the name of the file. For example, passing in "/folder/file"
 * requires the "folder" to be a valid directory in the root directory.
 *
 * @param path  The path provided
 * @param mode  Creation mode for the inode
 * @param extra Additional data provided for creation of the inode. Used by
 *              MODE_C_HLINK and MODE_C_SYMLINK to pass in the path or inode
 *              number being linked, otherwise NULL.
 *
 * @return The newly created inode number. A negative value indicates
 *         unsuccessful creation and is the error passed on.
 */
int create_inode(char *path, int mode, void *extra);

/**
 * Removes an inode at the specified absolute path.
 *
 * @param path The path provided
 *
 * @return The inode number that was deleted. A negative value indicates
 *         unsuccessful deletion and is the error passed on.
 */
int remove_inode(char *path);

/**
 * Restores an inode at the specified absolute path.
 *
 * @param path The path provided
 *
 * @return The inode number that was restored. A negative value indicates
 *         unsuccessful restoration and is the error passed on.
 */
int restore_inode(char *path);

/**
 * Finds the inode residing at an absolute path.
 *
 * @param path The path provided
 *
 * @return The ID of the inode that is at the path. A negative value
 *         indicates the inode not being found, or some other error
 *         occuring.
 */
int find_inode(char *path);

/**
 * Appends data to an inode.
 *
 * The data passed into the function will be truncated every
 * [EXT2_BLOCK_SIZE], with the data being distributed across
 * multiple blocks (if needed). The function assigns and claims
 * any required data blocks to the inode.
 *
 * @param ino  Inode being written to
 * @param data Data being written
 * @param len  The length of the data being written
 *
 * @return 0 on successful writing, an error code otherwise.
 */
int write_to_inode(int ino, char *data, size_t len);

#endif
