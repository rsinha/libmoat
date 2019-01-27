/* Testing hash tables
 * 15-122 Principles of Imperative Computation
 * Frank Pfenning
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include "hashtable.h"
#include "xalloc.h"
#include "contracts.h"

/* elements */
struct elem {
  char* word;			/* key */
  int count;			/* information */
};
typedef struct elem* elem;

/* key comparison */
bool equal(ht_key s1, ht_key s2) {
  return strcmp((char*)s1,(char*)s2) == 0;		/* different from C0! */
  /* or: !strcmp(s1,s2); */
}

/* extracting keys from elements */
ht_key elem_key(ht_elem e)
{ REQUIRES(e != NULL);
  return ((elem)e)->word;
}

/* hash function */
/* uses pseudo-random number generation */
/* converted to use unsigned int in C */
int hash(ht_key s, int m)
{ REQUIRES(m > 1);
  unsigned int a = 1664525;
  unsigned int b = 1013904223;	/* inlined random number generator */
  unsigned int r = 0xdeadbeef;	       /* initial seed */
  int len = strlen(s);		       /* different from C0! */
  int i; unsigned int h = 0;	       /* empty string maps to 0 */
  for (i = 0; i < len; i++)
    {
      h = r*h + ((char*)s)[i];	 /* mod 2^32 */
      r = r*a + b;	 /* mod 2^32, linear congruential random no */
    }
  h = h % m;			/* reduce to range */
  //@assert -m < (int)h && (int)h < m;
  int hx = (int)h;
  if (hx < 0) h += m;	/* make positive, if necessary */
  ENSURES(0 <= hx && hx < m);
  return hx;
}

/* max number of character in int: 10 + sign + '\0' = 12 */
#define MAXINT_CHARS 12

char* itoa(int n) {
  char* buf = xmalloc(MAXINT_CHARS * sizeof(char));
  snprintf(buf, MAXINT_CHARS, "%d", n);
  return buf;
}

void elem_free(ht_elem e) {
  free(((elem)e)->word);
  free(e);
}  

int main () {
  int n = (1<<10)+1; // start with 1<<10 for timing; 1<<9 for -d
  int num_tests = 10; // start with 1000 for timing; 10 for -d
  int i; int j;

  /* different from C0! */
  printf("Testing array of size %d with %d values, %d times\n",
	 n/5, n, num_tests);
  for (j = 0; j < num_tests; j++) {
    table H = table_new(n/5, &elem_key, &equal, &hash);
    for (i = 0; i < n; i++) {
      elem e = xmalloc(sizeof(struct elem));
      e->word = itoa(j*n+i);	/* diff from C0 */
      e->count = j*n+i;
      table_insert(H, e);
    }
    for (i = 0; i < n; i++) {
      char* s = itoa(j*n+i);
      assert(((elem)table_search(H, s))->count == j*n+i); /* "missed existing element" */
      free(s);
    }
    for (i = 0; i < n; i++) {
      char* s = itoa((j+1)*n+i);
      assert(table_search(H, s) == NULL); /* "found nonexistent element" */
      free(s);
    }
    table_free(H, &elem_free);
  }
  printf("All tests passed!\n");
  return 0;
}
