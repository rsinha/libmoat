/* Testing generic stacks
 * 15-122 Principles of Imperative Computation, Fall 2010
 * Frank Pfenning
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "xalloc.h"
#include "contracts.h"
#include "stacks.h"

void int_free(void* p) {
  free((int*)p);		/* this coercion is optional */
}

int main () {
  stack S = stack_new();
  int* x1 = xmalloc(sizeof(int));
  *x1 = 1;
  int* x2 = xmalloc(sizeof(int));
  *x2 = 2;
  push(x1, S);
  push(x2, S);
  stack_free(S, &int_free);
  /* or, alternatively, the next three lines */
  /*
  stack_free(S, NULL);
  free(x1);
  free(x2);
  */

  /* double free */
  /* creates memory errors */
  /* we cannot free, or apply any other operation */
  /* to a freed pointer; any such operation is undefined */
  /* next line would be error! */
  // stack_free(S, NULL);

  /* stack allocation */
  S = stack_new();
  int a1 = 1, a2 = 2;
  push(&a1, S);
  push(&a2, S);
  printf("%d\n", *(int*)pop(S)); /* must coerce here! */
  /* we cannot free elements allocated on the stack */
  /* they are implicilty deallocated when the functions */
  /* whose frame it belong to returns */
  /* next line would be error! */
  // stack_free(S, &int_free);

  /* arrays */
  /* pointer arithmetic */
  int* A = xcalloc(3, sizeof(int));
  A[0] = 0; A[1] = 1; A[2] = 2;
  push(A, S);			/* avoid this! */
  push(A+1, S);			/* at all cost! */
  push(&A[2], S);		/* if you must get a pointer, use address-of */
  /* we cannot deallocate pointers to the middle of objects */
  /* which stack_free(S, &int_free) would do */
  stack_free(S, NULL);
  free(A);			/* free manually */

  /* Everything should be clean here */
  printf("All tests succeeded!\n");
  return 0;
}
