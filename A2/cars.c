#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "traffic.h"

extern struct intersection isection;

/* [in_dir][out_dir][path] */
// TODO: U-turns must lock all quadrants
// TODO: Should be safe to convert direction enum to int
static int travel_paths[4][4][3] = {
    { // East
        {-1, -1, -1}, // East -> East
        {1, -1, -1}, // East -> North
        {1, 2, -1}, // East -> West
        {1, 2, 3} // East -> South
    },
    { // North
        {2, 3, 4}, // North -> East
        {-1, -1, -1}, // North -> North
        {2, -1, -1}, // North -> West
        {2, 3, -1} // North -> South
    },
    { // West
        {3, 4, -1}, // West -> East
        {1, 3, 4}, // West-> North
        {-1, -1, -1}, // West -> West
        {3, -1, -1} // West -> South
    },
    { // South
        {4, -1, -1}, // South -> East
        {1, 4, -1}, // South -> North
        {1, 2, 4}, // South -> West
        {-1, -1, -1} // South -> South
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
        //printf("lane->capacity=%d *lane.capacity=%d\n", lane->capacity, (*lane).capacity);
        lane->buffer=malloc(sizeof(struct car**) * LANE_LENGTH); // TODO: struct car** or just struct car?
        
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

    uint64_t tid;
    pthread_threadid_np(NULL, &tid);


    /* avoid compiler warning */
    //l = l;

    printf("car_arrive %llu\n", tid);

    // TODO: Synchronization - producer thread
    pthread_mutex_lock(&l->lock);

    /*if (l->in_cars == NULL){
        printf("car_arrive2\n");
        pthread_mutex_unlock(&l->lock);
        return NULL;
    }*/

    while(l->in_buf == l->capacity) {
        printf("car_arrive waiting %llu\n", tid);
        pthread_cond_wait(&l->producer_cv, &l->lock);
    }

    if (l->in_cars == NULL) {
        pthread_mutex_unlock(&l->lock);
        return NULL; // TODO: What to do if this is the case?
    }

    // TODO: LIFO?
    // Remove the car from in_cars


    next_car = l->in_cars;
    
    l->in_cars = next_car->next; // TODO: NULL checking
    next_car-> next = NULL;


    l->buffer[l->tail] = next_car;
    l->tail++;
    if (l->tail == l->capacity) {
        l->tail = 0;
    }
    l->in_buf++;
    l->inc--;


    // move from in_cars to buffer
    // in_buf++
    // update tail of buffer
    // inc--

    pthread_cond_signal(&l->consumer_cv);
    pthread_mutex_unlock(&l->lock);

    printf("car_arrive done %llu\n", tid);
    //printf("Completed car_arrive %d\n", )

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
    struct lane out_lane;
    int *path;
    int path_loop;
    uint64_t tid;
    pthread_threadid_np(NULL, &tid);

    // TODO: Consumer
    pthread_mutex_lock(&l->lock);
    while(l->in_buf == 0) {
        printf("car_cross waiting %llu\n", tid);
        pthread_cond_wait(&l->consumer_cv, &l->lock);
    }

    // Get a car out of the buffer
    crossing = l->buffer[l->head];
    l->buffer[l->head] = NULL;
    l->head++;
    if (l->head == l->capacity) {
        l->head = 0;
    }
    l->in_buf--;

    // Move car into the new lane - TODO: Should lock in different section?
    out_lane = isection.lanes[crossing->out_dir];

    // Go through the intersection
    path = compute_path(crossing->in_dir, crossing->out_dir);


    for (path_loop = 0 ; path_loop < 3 ; path_loop++) {
        printf("%d ", path[path_loop]);
    }
    printf("\n");

        // TODO: Passed? Piazza

    pthread_cond_signal(&l->producer_cv);
    pthread_mutex_unlock(&l->lock);

    printf("car_cross done %llu\n", tid);

    return NULL;
}

/* Converts a direction enum to index valid for the travel_paths array */
int direction_to_index(enum direction dir) {
    switch (dir) {
    case EAST: return 0;
    case NORTH: return 1;
    case WEST: return 2;
    case SOUTH: return 3;
    default:
        return -1;
    }
}

/**
 * TODO: Fill in this function
 *
 * Given a car's in_dir and out_dir return a sorted 
 * list of the quadrants the car will pass through.
 * 
 */
int *compute_path(enum direction in_dir, enum direction out_dir) {
    int in_dir_index;
    int out_dir_index;

    in_dir_index = direction_to_index(in_dir);
    out_dir_index = direction_to_index(out_dir);

    return travel_paths[in_dir_index][out_dir_index];
}
