#ifndef _UTILS_H_
#define _UTILS_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "sgx_tcrypto.h"

/***************************************************
                MATH UTILITIES
 ***************************************************/

size_t min(size_t a, size_t b);
size_t max(size_t a, size_t b);

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
size_t list_size(ll_t *list);
//inserts value at the tail of the linked list
void list_insert_value(ll_t *list, void *value);
//removes value from the linked list
bool list_delete_value(ll_t *list, void *value);
//finds first node in the linked list which satisfies pred
void *list_find_value(ll_t *list, bool (*pred)(void *));
//iterator to invoke has_next and get_next
ll_iterator_t *list_create_iterator(ll_t *list);
//free resources used by the iterator
void list_destroy_iterator(ll_iterator_t *iter);
//does the list have a next item not yet consumed by iter?
bool list_has_next(ll_iterator_t *iter);
//return the next item in the list
void *list_get_next(ll_iterator_t *iter);

/***************************************************
            CRYPTO UTILITIES
 ***************************************************/

size_t hkdf(uint8_t *ikm, size_t ikm_len, uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len);
size_t hmac_sha256(uint8_t *key, size_t key_len, uint8_t *msg, size_t msg_len, sgx_sha256_hash_t *out);

#endif
