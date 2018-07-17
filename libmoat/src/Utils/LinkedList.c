#include "api/Utils.h"
#include <stdlib.h>
#include <assert.h>

/***************************************************
            DEFINITIONS FOR INTERNAL USE
 ***************************************************/

typedef struct _ll_node
{
    void *value;
    struct _ll_node *next;
} ll_node_t;

/***************************************************
            PUBLIC API IMPLEMENTATION
 ***************************************************/

ll_t *list_create() {
    ll_t *result = malloc(sizeof(ll_t));
    assert(result != NULL);
    result->head = NULL;
    return result;
}

//returns the size of the linked list
size_t list_size(ll_t *list)
{
    if (list == NULL) { return 0; }
    
    ll_node_t *iter = list->head;
    size_t count = 0;
    
    while (iter != NULL)
    {
        iter = iter->next;
        count += 1;
    }
    return count;
}

//inserts value at the tail of the linked list
void list_insert_value(ll_t *list, void *value)
{
    if (list == NULL || value == NULL) { return; } //error-checking on inputs
    
    ll_node_t *node = (ll_node_t *) malloc(sizeof(ll_node_t)); //malloc the new node
    assert(node != NULL);
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

//removes value from the linked list, but doesn't free the value (caller's responsibility)
bool list_delete_value(ll_t *list, void *value)
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
void *list_find_value(ll_t *list, bool (*pred)(void *))
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

ll_iterator_t *list_create_iterator(ll_t *list)
{
    ll_iterator_t *iter = malloc(sizeof(ll_iterator_t));
    assert(iter != NULL);
    iter->next_node = list->head;
    return iter;
}

void list_destroy_iterator(ll_iterator_t *iter)
{
    if (iter == NULL) { return; }
    free(iter);
}

bool list_has_next(ll_iterator_t *iter)
{
    return (iter->next_node != NULL) ? true : false;
}

void *list_get_next(ll_iterator_t *iter)
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

/***************************************************
                    UNIT TESTS
 ***************************************************/

bool test0()
{
    int values[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    ll_t *g_list = NULL;
    ll_iterator_t *iter = NULL;
    
    g_list = malloc(sizeof(ll_t));
    assert(g_list != NULL);
    g_list->head = NULL;
    
    list_insert_value(g_list, &values[0]);
    list_insert_value(g_list, &values[1]);
    list_insert_value(g_list, &values[2]);
    assert(list_size(g_list) == 3);
    iter = list_create_iterator(g_list);
    //while(list_has_next(iter)) { _moat_print_debug("%d,", *((int *) list_get_next(iter))); } _moat_print_debug("\n");
    list_destroy_iterator(iter);
    
    list_delete_value(g_list, &values[2]);
    assert(list_size(g_list) == 2);
    iter = list_create_iterator(g_list);
    //while(list_has_next(iter)) { _moat_print_debug("%d,", *((int *) list_get_next(iter))); } _moat_print_debug("\n");
    list_destroy_iterator(iter);
    
    list_insert_value(g_list, &values[3]);
    assert(list_size(g_list) == 3);
    iter = list_create_iterator(g_list);
    //while(list_has_next(iter)) { _moat_print_debug("%d,", *((int *) list_get_next(iter))); } _moat_print_debug("\n");
    list_destroy_iterator(iter);
    
    list_delete_value(g_list, &values[0]);
    assert(list_size(g_list) == 2);
    iter = list_create_iterator(g_list);
    //while(list_has_next(iter)) { _moat_print_debug("%d,", *((int *) list_get_next(iter))); } _moat_print_debug("\n");
    list_destroy_iterator(iter);
    
    list_insert_value(g_list, &values[5]);
    assert(list_size(g_list) == 3);
    iter = list_create_iterator(g_list);
    //while(list_has_next(iter)) { _moat_print_debug("%d,", *((int *) list_get_next(iter))); } _moat_print_debug("\n");
    list_destroy_iterator(iter);
    
    list_delete_value(g_list, &values[1]);
    list_delete_value(g_list, &values[3]);
    list_delete_value(g_list, &values[5]);
    assert(list_size(g_list) == 0);
    iter = list_create_iterator(g_list);
    //while(list_has_next(iter)) { _moat_print_debug("%d,", *((int *) list_get_next(iter))); } _moat_print_debug("\n");
    list_destroy_iterator(iter);

    free(g_list);
}


