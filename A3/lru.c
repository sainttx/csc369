#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include "pagetable.h"

extern int memsize;

extern int debug;

extern struct frame *coremap;

// A simple linked list structure that the algorithm uses to
// keep track of frames that have been recently used.
typedef struct node {
	int frame;
	struct node *next;
} node_t;

node_t *head; // The head contains the most recently used frame
node_t *tail; // The tail of the list is the least recently used

/*
 * Removes a frame from the list, if present. This method
 * will properly update the head and tail variables accordingly.
 */
void remove_if_present(int frame) {
	node_t *curr = head;
	node_t *prev = NULL;

	while (curr) {
		// Check if the current iterated node is the
		// correct frame - remove if so.
		if (curr->frame == frame) {
			if (curr == head) {
				head = curr->next; // Update head of list
			} else {
				if (curr == tail) {
					tail = prev; // Update tail of list
				}
				prev->next = curr->next;
			}

			free(curr);
			break;
		}

		// Move to the next node
		prev = curr;
		curr = curr->next;
	}
}

/* Page to evict is chosen using the accurate LRU algorithm.
 * Returns the page frame number (which is also the index in the coremap)
 * for the page that is to be evicted.
 */
int lru_evict() {
	assert(tail != NULL);
	int frame = tail->frame;
	remove_if_present(frame);
	return frame;
}

/* This function is called on each access to a page to update any information
 * needed by the lru algorithm.
 * Input: The page table entry for the page that is being accessed.
 */
void lru_ref(pgtbl_entry_t *p) {
	int frame = p->frame >> PAGE_SHIFT;

	// Remove the frame from the list if present (prevent duplicates)
	remove_if_present(frame);

	// Insert the frame as the head (most recently referenced)
	node_t *new_head = (node_t*) malloc(sizeof(node_t));
	new_head->frame = frame;
	new_head->next = head;
	head = new_head;

	// Update the tail if it hasn't been set yet
	if (!tail) {
		tail = new_head;
	}
}


/* Initialize any data structures needed for this
 * replacement algorithm
 */
void lru_init() {
	head = NULL;
	tail = NULL;
}
