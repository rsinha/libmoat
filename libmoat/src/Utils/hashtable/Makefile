# call with make D='-DDEBUG -g' for debug mode
FLAGS=-Wall -Wextra -std=c99 -pedantic -Werror
# D=-DDEBUG -g
GCC=gcc ${D} ${FLAGS}

default: stacks

stacks : contracts.h xalloc.h xalloc.c stacks.h stacks.c stacks-test.c
	$(GCC) xalloc.c stacks.c stacks-test.c -o stacks

hashtable : contracts.h xalloc.h xalloc.c hashtable.h hashtable.c hashtable-test.c
	$(GCC) xalloc.c hashtable.c hashtable-test.c -o hashtable

clean :
	${RM} -rf a.out a.out.dSYM
	${RM} -rf stacks stacks.dSYM
	${RM} -rf hashtable hashtable.dSYM
