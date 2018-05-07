#include <stddef.h>

/***************************************************
 PUBLIC API
 ***************************************************/

char * strcpy(char *strDest, const char *strSrc)
{
    //assert(strDest != NULL && strSrc != NULL);
    char *temp = strDest;
    while(*strDest++ = *strSrc++); // or while((*strDest++=*strSrc++) != '\0');
    return temp;
}