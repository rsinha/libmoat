/* Stacks
 * 15-122 Principles of Imperative Computation, Fall 2010
 * Frank Pfenning
 */

#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include "xalloc.h"
#include "contracts.h"
#include "stacks.h"

/* Linked lists */

typedef struct list* list;
struct list {
  void* data;			/* generic data */
  list next;
};

void list_free(list p, void (*data_free)(void* x)) {
  while (p != NULL) {
    list q = p->next;
    if (p->data != NULL && data_free != NULL)
      (*data_free)(p->data);
    free(p);
    p = q;
  }
  return;
}

bool is_segment(list start, list end)
{ list p = start;
  while (p != end) {
    if (p == NULL) return false;
    p = p->next;
  }
  return true;
}

bool is_circular(list l)
{ if (l == NULL) return false;
  { list t = l;       /* tortoise */
    list h = l->next; /* hare */
    ASSERT(is_segment(t, h));
    while (t != h)
      //@loop_invariant is_segment(t, h);
      { ASSERT(is_segment(t, h)); /* not quite the same as @loop_variant */
	if (h == NULL || h->next == NULL) return false;
	t = t->next;
	h = h->next->next;
      }
    return true;
  }
}

/* Stacks */ 

struct stack {
  list top;
};

bool is_stack (stack S) {
  return is_segment(S->top, NULL);
}

bool stack_empty(stack S)
{
  REQUIRES(is_stack(S));
  return S->top == NULL;
}

stack stack_new()
{
  REQUIRES(true);
  stack S = xmalloc(sizeof(struct stack));
  S->top = NULL;
  ENSURES(is_stack(S) && stack_empty(S));
  return S;
}

void stack_free(stack S, void (*data_free)(void* x)) {
  REQUIRES(is_stack(S));
  list_free(S->top, data_free);
  free(S);
}


void push(void* x, stack S)
{
  REQUIRES(is_stack(S));
  list first = xmalloc(sizeof(struct list));
  first->data = x;
  first->next = S->top;
  S->top = first;
  ENSURES(is_stack(S) && !stack_empty(S));
}

void* pop(stack S)
{ REQUIRES(is_stack(S) && !stack_empty(S));
  assert(S != NULL && S->top != NULL);
  void* x = S->top->data;	/* save old stack element to return */
  list q = S->top;		/* save old list node to free */
  S->top = S->top->next;
  free(q);			/* free old list node */
  ENSURES(is_stack(S));
  return x;			/* return old stack element */
}
