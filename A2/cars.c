#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "traffic.h"

extern struct intersection isection;

/* [in_dir][out_dir] : path */
static int travel_paths[4][4][4] = {
    { // North
        {1, 2, 3, 4}, // North -> North
        {2, -1, -1, -1}, // North -> West
        {2, 3, -1, -1}, // North -> South
        {2, 3, 4, -1} // North -> East
    },
    { // West
        {1, 3, 4, -1}, // West-> North
        {1, 2, 3, 4}, // West -> West
        {3, -1, -1, -1}, // West -> South
        {3, 4, -1, -1} // West -> East
    },
    { // South
        {1, 4, -1, -1}, // South -> North
        {1, 2, 4, -1}, // South -> West
        {1, 2, 3, 4}, // South -> South
        {4, -1, -1} // South -> East
    },
    { // East
        {1, -1, -1, -1}, // East -> North
        {1, 2, -1, -1}, // East -> West
        {1, 2, 3, -1}, // East -> South
        {1, 2, 3, 4} // East -> East
    },
};

/**
 * Populate the car lists by parsing a file where each line has
 * the following structure:
 *
 * <id> <in_direction> <out_direction>
 *
 * Each car is added to the list that corresponds with
 * its in_direction
 *
 * Note: this also updates 'inc' on each of the lanes
 */
void parse_schedule(char *file_name) {
    int id;
    struct car *cur_car;
    struct lane *cur_lane;
    enum direction in_dir, out_dir;
    FILE *f = fopen(file_name, "r");

    /* parse file */
    while (fscanf(f, "%d %d %d", &id, (int*)&in_dir, (int*)&out_dir) == 3) {

        /* construct car */
        cur_car = malloc(sizeof(struct car));
        cur_car->id = id;
        cur_car->in_dir = in_dir;
        cur_car->out_dir = out_dir;

        /* append new car to head of corresponding list */
        cur_lane = &isection.lanes[in_dir];
        cur_car->next = cur_lane->in_cars;
        cur_lane->in_cars = cur_car;
        cur_lane->inc++;
    }

    fclose(f);
}

/**
 * TODO: Fill in this function
 *
 * Do all of the work required to prepare the intersection
 * before any cars start coming
 *
 */
void init_intersection() {
    int i;
    struct intersection* intersect;
    struct lane* lane;

    intersect = &isection;

    // Initialize all quadrant mutexes and lanes
    for (i = 0 ; i < 4 ; i++) {
        // Initialize the quadrant mutex
        pthread_mutex_init(&intersect->quad[i], NULL);

        // Initialize the lane
        lane = &intersect->lanes[i];
        pthread_mutex_init(&lane->lock, NULL);
        pthread_cond_init(&lane->producer_cv, NULL);
        pthread_cond_init(&lane->consumer_cv, NULL);
        lane->capacity = LANE_LENGTH;
        lane->buffer=malloc(sizeof(struct car**) * LANE_LENGTH);
        lane->inc = 0;
        lane->passed = 0;
        lane->head = 0;
        lane->tail = 0;
        lane->in_buf = 0;
    }
}

/**
 * TODO: Fill in this function
 *
 * Populates the corresponding lane with cars as room becomes
 * available. Ensure to notify the cross thread as new cars are
 * added to the lane.
 *
 */
void *car_arrive(void *arg) {
    struct lane *l = arg;
    struct car *next_car;

    while (l->inc > 0) {
        pthread_mutex_lock(&l->lock);

        // Implement mesa monitor, if the buffer is full we must wait
        while(l->in_buf == l->capacity) {
            pthread_cond_wait(&l->producer_cv, &l->lock);
        }

        // We return if there are no more cars that are passing
        // through the lane
        if (l->inc == 0) {
            pthread_mutex_unlock(&l->lock);
            return NULL;
        }

        next_car = l->in_cars;
        l->in_cars = next_car->next;
        next_car-> next = NULL;

        l->buffer[l->tail] = next_car;
        l->tail++;
        l->tail = l->tail % l->capacity; // Round robin
        l->in_buf++;
        l->inc--;

        pthread_cond_signal(&l->consumer_cv);
        pthread_mutex_unlock(&l->lock);
    }
    return NULL;
}

/**
 * TODO: Fill in this function
 *
 * Moves cars from a single lane across the intersection. Cars
 * crossing the intersection must abide the rules of the road
 * and cross along the correct path. Ensure to notify the
 * arrival thread as room becomes available in the lane.
 *
 * Note: After crossing the intersection the car should be added
 * to the out_cars list of the lane that corresponds to the car's
 * out_dir. Do not free the cars!
 *
 *
 * Note: For testing purposes, each car which gets to cross the
 * intersection should print the following three numbers on a
 * new line, separated by spaces:
 *  - the car's 'in' direction, 'out' direction, and id.
 *
 * You may add other print statements, but in the end, please
 * make sure to clear any prints other than the one specified above,
 * before submitting your final code.
 */
void *car_cross(void *arg) {
    struct lane *l = arg;
    struct car *crossing;
    struct lane *out_lane;
    int *path;
    int i;

    while (l->in_cars != NULL || l->in_buf > 0) {
        pthread_mutex_lock(&l->lock);
        while(l->in_buf == 0) {
            // If no other cars are waiting to arrive in the queue
            // we exit to prevent deadlock
            /*if (l->inc == 0) {
                pthread_mutex_unlock(&l->lock);
                return NULL;
            }*/
            pthread_cond_wait(&l->consumer_cv, &l->lock);
        }

        // Get the car that's going to be crossing
        crossing = l->buffer[l->head];
        l->buffer[l->head] = NULL;
        l->head++;
        l->head = l->head % l->capacity; // Round robin

        // Move the car through the intersection and into the new lane
        out_lane = &isection.lanes[crossing->out_dir];
        path = compute_path(crossing->in_dir, crossing->out_dir);

        for (i = 0 ; i < 4 ; i++) {
            if (path[i]!=-1) {
                pthread_mutex_lock(&isection.quad[path[i]-1]);
            }
        }

        // Acquire the out lane lock only if it is a different lane,
        // since we already have a lock acquired on the current
        // lane.
        if (out_lane != l) {
            pthread_mutex_lock(&out_lane->lock);
        }

        crossing->next = out_lane->out_cars;
        out_lane->out_cars = crossing;
        out_lane->passed++;
        printf("%d %d %d\n", crossing->in_dir, crossing->out_dir, crossing->id);

        // Release all locks
        if (out_lane != l) {
            pthread_mutex_unlock(&out_lane->lock);
        }

        for (i = 0 ; i < 4 ; i++) {
            if (path[i]!=-1) {
                pthread_mutex_unlock(&isection.quad[path[i]-1]);
            }
        }

        // Update the current lane
        l->in_buf--;

        pthread_cond_signal(&l->producer_cv);
        pthread_mutex_unlock(&l->lock);
    }

    return NULL;
}

/**
 * TODO: Fill in this function
 *
 * Given a car's in_dir and out_dir return a sorted 
 * list of the quadrants the car will pass through.
 * 
 */
int *compute_path(enum direction in_dir, enum direction out_dir) {
    return travel_paths[in_dir][out_dir];
}
