#include "api/Utils.h"
#include <stdlib.h>

/***************************************************
 DEFINITIONS FOR INTERNAL USE
 ***************************************************/

typedef struct _ll_node
{
    void *value;
    struct _ll_node *next;
} ll_node_t;

/***************************************************
 PUBLIC API
 ***************************************************/

//returns the size of the linked list
uint32_t list_size(ll_t *list)
{
    if (list == NULL) { return 0; }
    
    ll_node_t *iter = list->head;
    uint32_t count = 0;
    
    while (iter != NULL)
    {
        iter = iter->next;
        count += 1;
    }
    return count;
}

//inserts value at the tail of the linked list
void insert_value(ll_t *list, void *value)
{
    if (list == NULL || value == NULL) { return; } //error-checking on inputs
    
    ll_node_t *node = (ll_node_t *) malloc(sizeof(ll_node_t)); //malloc the new node
    node->value = value;
    node->next = NULL; //we are going to insert at the tail
    
    if (list->head == NULL) { //is the list empty?
        list->head = node; return;
    }
    
    //if we got here, then we have a list of size >= 1
    ll_node_t *iter = (ll_node_t *) list->head;
    ll_node_t *iter_next = ((ll_node_t *) list->head)->next;
    while (iter_next != NULL)
    {
        iter_next = iter_next->next;
        iter = iter->next;
    }
    
    //at this poimt. iter is at the tail and iter_next is NULL
    iter->next = node;
}

//removes value from the linked list
bool delete_value(ll_t *list, void *value)
{
    if (list == NULL || value == NULL) { return false; } //error-checking on inputs
    
    if (list->head == NULL) { return false; } //empty list can't contain value
    
    //if we got here, then we have a list of size >= 1
    
    if (((ll_node_t *) list->head)->value == value) { //is the head what we are looking for?
        free(list->head);
        list->head = ((ll_node_t *) list->head)->next;
        return true;
    }
    
    ll_node_t *iter = (ll_node_t *) list->head;
    ll_node_t *iter_next = ((ll_node_t *) list->head)->next;
    
    while (iter_next != NULL)
    {
        if (iter_next->value == value) {
            iter->next = iter_next->next;
            free(iter_next); //value must be freed outside
            return true;
        }
        iter_next = iter_next->next;
        iter = iter->next;
    }
    
    return false;
}

//finds first node in the linked list which satisfies pred
void *find_value(ll_t *list, bool (*pred)(void *))
{
    if(list == NULL || pred == NULL) { return NULL; } //error-checking on inputs
    
    ll_node_t *iter = (ll_node_t *) list->head;
    while (iter != NULL)
    {
        if ((*pred)(iter->value)) {
            return iter->value;
        }
        iter = iter->next;
    }
    return NULL; //didn't find anything
}

ll_iterator_t *create_iterator(ll_t *list)
{
    ll_iterator_t *iter = malloc(sizeof(ll_iterator_t));
    iter->next_node = list->head;
    return iter;
}

void destroy_iterator(ll_iterator_t *iter)
{
    if (iter == NULL) { return; }
    free(iter);
}

bool has_next(ll_iterator_t *iter)
{
    return (iter->next_node != NULL);
}

void *get_next(ll_iterator_t *iter)
{
    if (iter == NULL) { return NULL; }
    
    if (iter->next_node != NULL) {
        ll_node_t *result = (ll_node_t *) iter->next_node;
        iter->next_node = ((ll_node_t *) iter->next_node)->next;
        return result->value;
    } else {
        return NULL;
    }
}
