#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include "pagetable.h"


extern int memsize;

extern int debug;

extern struct frame *coremap;

int clock_head;

/* Page to evict is chosen using the clock algorithm.
 * Returns the page frame number (which is also the index in the coremap)
 * for the page that is to be evicted.
 */
int clock_evict() {
	// Loop through coremap until we find a frame that doesn't have the 
	// PG_REF bit set, removing the bit for frames passed over.
	while (coremap[clock_head].pte->frame & PG_REF) {
		coremap[clock_head].pte->frame &= ~PG_REF; // Remove ref bit
		clock_head = (clock_head + 1) % memsize; // Increment clock pointer
	}
	return clock_head;
}

/* This function is called on each access to a page to update any information
 * needed by the clock algorithm.
 * Input: The page table entry for the page that is being accessed.
 */
void clock_ref(pgtbl_entry_t *p) {

	return;
}

/* Initialize any data structures needed for this replacement
 * algorithm. 
 */
void clock_init() {
	clock_head = 0;
}
