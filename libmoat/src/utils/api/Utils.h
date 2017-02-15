#ifndef _UTILS_H_
#define _UTILS_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/***************************************************
                MATH UTILITIES
 ***************************************************/

size_t min(size_t a, size_t b);

/***************************************************
            LINKED LIST UTILITIES
 ***************************************************/

typedef struct
{
    void *head; //type ll_node_t
} ll_t;

typedef struct
{
    void *next_node; //type ll_node_t
} ll_iterator_t;

//returns the size of the linked list
uint32_t list_size(ll_t *list);
//inserts value at the tail of the linked list
void insert_value(ll_t *list, void *value);
//removes value from the linked list
bool delete_value(ll_t *list, void *value);
//finds first node in the linked list which satisfies pred
void *find_value(ll_t *list, bool (*pred)(void *));
//iterator to invoke has_next and get_next
ll_iterator_t *create_iterator(ll_t *list);
//free resources used by the iterator
void destroy_iterator(ll_iterator_t *iter);
//does the list have a next item not yet consumed by iter?
bool has_next(ll_iterator_t *iter);
//return the next item in the list
void *get_next(ll_iterator_t *iter);

#endif
