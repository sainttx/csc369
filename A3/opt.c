#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include "pagetable.h"
#include "sim.h"

extern int debug;

extern struct frame *coremap;

// Linked list structure to track the order in which 
// virtual addresses are called
typedef struct node {
	addr_t vaddr;
	struct node *next;
} node_t;

node_t *next_trace; // The next trace that will be referenced

/* Page to evict is chosen using the optimal (aka MIN) algorithm. 
 * Returns the page frame number (which is also the index in the coremap)
 * for the page that is to be evicted.
 */
int opt_evict() {
	int i;
	int frame = -1;
	int max = -1;

	for (i = 0 ; i < memsize ; i++) {
		if (coremap[i].distance > max) {
			frame = i;
			max = coremap[i].distance;
		}
	}

	return frame;
}

void calculate_frame_distance(struct frame f) {
	f.distance = -1; // Initial setting of -1 in case it never appears
	int distance = 0;
	node_t *curr = NULL;

	while (curr) {
		if (curr->vaddr == f.vaddr) {
			f.distance = distance;
			return;
		}
		distance++;
		curr = curr->next;
	}
}

/* This function is called on each access to a page to update any information
 * needed by the opt algorithm.
 * Input: The page table entry for the page that is being accessed.
 */
void opt_ref(pgtbl_entry_t *p) {
	calculate_frame_distance(coremap[p->frame]);
	next_trace = next_trace->next;
}

/* Initializes any data structures needed for this
 * replacement algorithm.
 */
void opt_init() {
	char buf[MAXLINE];
	addr_t vaddr = 0;
	char type;
	FILE* tfp;
	
	if((tfp = fopen(tracefile, "r")) == NULL) {
		perror("Error opening tracefile:");
		exit(1);
	}

	node_t *prev;

	while(fgets(buf, MAXLINE, tfp) != NULL) {
		if(buf[0] != '=') {
			sscanf(buf, "%c %lx", &type, &vaddr);

			node_t *trace = (node_t*) malloc(sizeof(node_t));
			trace->vaddr = vaddr;

			// If it's the first trace read, it's now the head of LL
			if (!next_trace) {
				next_trace = trace;
			} else {
				prev->next = next_trace;
			}

			prev = trace;
		} else {
			continue;
		}

	}
}

