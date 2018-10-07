/*
 *   MIRACL Comba's method for ultimate speed modular multiplication
 *   mrcomba.tpl 
 *
 *   See "Exponentiation Cryptosystems on the IBM PC", IBM Systems
 *   Journal Vol. 29 No. 4 1990. Comba's method has been extended to 
 *   implement Montgomery reduction. 
 *
 *   Here the inner loops of the basic multiplication, squaring and 
 *   Montgomery's redc() functions are completely unravelled, and 
 *   reorganised for maximum possible speed. 
 *
 *   This approach is recommended for maximum speed where parameters
 *   are fixed and compute resources are constrained. The processor must 
 *   support an unsigned multiply instruction, and should have a carry flag.
 *
 *   This file is a template. To fill in the gaps and create mrcomba.c, 
 *   you must run the mex.c program to insert the C or assembly language 
 *   macros from the appropriate .mcs file. For use with C MR_NOASM must
 *   be defined in mirdef.h
 *
 *   This method would appear to be particularly useful for implementing 
 *   fast Elliptic Curve Cryptosystems over GF(p) and fast 1024-bit RSA
 *   decryption.
 *
 *   The #define MR_COMBA in mirdef.h determines the FIXED size of 
 *   modulus to be used. This *must* be determined at compile time. 
 *
 *   Note that this module can generate a *lot* of code for large values 
 *   of MR_COMBA. This should have a maximum value of 8-16. Any larger 
 *   that and you should define MR_KCM instead - see mrkcm.tpl
 *
 *   Note that on some processors it is *VITAL* that arrays be aligned on 
 *   4-byte boundaries
 *
 *  **** This code does not like -fomit-frame-pointer using GCC  ***********
 *
 *   Copyright (c) 1988-2001 Shamus Software Ltd.
 */

#include "miracl.h"    
#ifdef MR_SSE2_INTRINSICS
  #ifdef __GNUC__
    #include <xmmintrin.h>
  #else
    #include <emmintrin.h>
  #endif
#endif


#ifdef MR_COMBA
#if INLINE_ASM == 1    
#define N 2
#define POINTER WORD PTR  
#define PBP bp   
#define PBX bx   
#define PSI si   
#define PDI di   
#define DSI si   
#define DDI di   
#define DBP bp   
#define DAX ax   
#define DCX cx   
#define DDX dx   
#endif   
 
#if INLINE_ASM == 2    
#define N 4
#define POINTER DWORD PTR   
#define PBP bp   
#define PBX bx   
#define PSI si   
#define PDI di   
#define DSI esi  
#define DDI edi  
#define DBP ebp  
#define DAX eax  
#define DCX ecx  
#define DDX edx  
#endif           
  
#if INLINE_ASM == 3    
#define N 4
#define POINTER DWORD PTR   
#define PBP ebp   
#define PBX ebx   
#define PSI esi   
#define PDI edi   
#define DSI esi  
#define DDI edi  
#define DBP ebp  
#define DAX eax  
#define DCX ecx  
#define DDX edx  
#endif           
  
/* NOTE! z must be distinct from x and y */

void comba_mult(_MIPD_ big x,big y,big z) 
{ /* comba multiplier */
    int i;
    mr_small *a,*b,*c;
   
#ifdef MR_SSE2_INTRINSICS
    __m128i xmm0,xmm1,xmm2,xmm3,xmm4,xmm7;
#endif
#ifdef MR_ITANIUM
    register mr_small lo1,hi1,lo2,hi2,sumlo,sumhi,extra,ma,mb;
#else
#ifdef MR_NOASM 
 #ifdef mr_qltype
    mr_large pp1;
    mr_vlarge sum;
 #else
    register mr_small extra,s0,s1;
    mr_large pp1,pp2,sum;
 #endif
#endif
#endif
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
   
    for (i=2*MR_COMBA;i<(int)(z->len&MR_OBITS);i++) z->w[i]=0;
  
    z->len=2*MR_COMBA;
    a=x->w; b=y->w; c=z->w;
/*** MULTIPLY ***/      /* multiply a by b, result in c */
    if (z->w[2*MR_COMBA-1]==0) mr_lzero(z);
}   
 
/* NOTE! z and x must be distinct */

void comba_square(_MIPD_ big x,big z)  
{ /* super comba squarer */
    int i;
    mr_small *a,*c;
  
#ifdef MR_ITANIUM
    register mr_small lo1,hi1,lo2,hi2,sumlo,sumhi,extra,ma,mb;
#else
#ifdef MR_NOASM
 #ifdef mr_qltype
    mr_large pp1;
    mr_vlarge sum;
 #else
    register mr_small extra,s0,s1;
    mr_large pp1,pp2,sum;
 #endif
#endif
#endif
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
 
    for (i=2*MR_COMBA;i<(int)(z->len&MR_OBITS);i++) z->w[i]=0;  
 
    z->len=2*MR_COMBA;
    a=x->w; c=z->w;
/*** SQUARE ***/    /* squares a, result in b */
    if (z->w[2*MR_COMBA-1]==0) mr_lzero(z); 
}                        
                         
/* NOTE! t and z must be distinct! */

void comba_redc(_MIPD_ big t,big z)     
{  /* super comba Montgomery redc() function */                      
    mr_small carry,su;
#ifdef MR_ITANIUM
    register mr_small lo1,hi1,lo2,hi2,sumlo,sumhi,extra,ma,mb,sp,u;
#else
#ifdef MR_NOASM
    mr_large u;
#ifndef MR_SPECIAL
 #ifdef mr_qltype
    register mr_small sp;
    mr_large pp1;
    mr_vlarge sum;
 #else
    register mr_small sp,extra,s0,s1;
    mr_large pp1,pp2,sum;
 #endif
#endif
#endif
#endif
    unsigned int i;
    big w,modulus;
    mr_small *a,*b;
#ifndef MR_SPECIAL
    BOOL need_subtract;
    mr_small ndash;
#endif
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

#ifdef MR_SPECIAL


/* !!! Implement here a "special" fast method for modular reduction,
   for a particular modulus. Implemented here for 2^192-2^64-1       
   and 2^224-2^96+1 on a 32 bit processor.
   See for example "Software Implementation of the NIST Elliptic
   Curves Over Prime Fields", Brown et al., Report #36, 2000 available
   from www.cacr.math.uwaterloo.ca 

   The generated code can be manually optimised further.....
*/
    int overshoot;
    mr_small k[MR_COMBA],sn;
    mr_small *c;
    modulus=mr_mip->modulus;     
    for (i=MR_COMBA;i<(int)(z->len&MR_OBITS);i++) z->w[i]=0;
 /*      zero(z);   */
    z->len=MR_COMBA;

#ifdef MR_PSEUDO_MERSENNE

    sn=(mr_small)0-modulus->w[0];  /* Modulus is 2^{MIRACL*MR_COMBA}-c. Here we calculate c */

/* .. where c MUST be a word sized ... */


    a=&(t->w[MR_COMBA]);
    b=k;
    c=z->w;

/*** PMULT ***/

    a=c;

/*** INCREMENT ***/
    overshoot=carry;
    b=t->w;

/*** INCREMENT ***/
    overshoot+=carry;
    
    b=modulus->w;
    while(overshoot>0)
    {
/*** DECREMENT ***/
        overshoot-=carry;
    }
    if (z->w[MR_COMBA-1]>=modulus->w[MR_COMBA-1])
    {
        if (mr_compare(z,modulus)>=0)
        {
/*** DECREMENT ***/
        }
    }
    if (z->w[MR_COMBA-1]==0) mr_lzero(z);

#else

#if MIRACL==64

   #if MR_COMBA == 3
/* Special Code for 2^192-2^64-1 - assuming 64-bit processor */

    a=t->w; b=k; c=z->w;
    k[0]=k[1]=a[3]; k[2]=0;

/*** ADDITION ***/
    overshoot=carry;  
    a=c;  c=t->w;
    k[0]=0;k[1]=k[2]=c[4];

/*** INCREMENT ***/
    overshoot+=carry;
    k[0]=k[1]=k[2]=c[5];

/*** INCREMENT ***/
    overshoot+=carry;
    b=modulus->w;
    while(overshoot>0)
    {
/*** DECREMENT ***/
        overshoot-=carry;
    }
    if (z->w[MR_COMBA-1]>=modulus->w[MR_COMBA-1])
    {
        if (mr_compare(z,modulus)>=0)
        {
/*** DECREMENT ***/
        }
    }
    if (z->w[MR_COMBA-1]==0) mr_lzero(z);

   #endif
#endif


#if MIRACL==8
   #if MR_COMBA==20

   /* 2^160-2^112+2^64+1 */

/* faster way - keep a[20] to a[39] in registers r2-r21. 
*/

   a=t->w; b=k; c=z->w;

   k[0]=k[8]=a[38]; k[2]=k[4]=k[6]=k[10]=k[12]=0; k[14]=a[20]; k[16]=a[22]; k[18]=a[24];
   k[1]=k[9]=a[39]; k[3]=k[5]=k[7]=k[11]=k[13]=0; k[15]=a[21]; k[17]=a[23]; k[19]=a[25];

/*** ADDITION ***/
    overshoot=carry;
    a=c; c=t->w;
    k[0]=k[2]=k[4]=k[6]=0; k[8]=k[14]=k[16]=c[34]; k[10]=c[36]; k[12]=c[24];  k[18]=0;
    k[1]=k[3]=k[5]=k[7]=0; k[9]=k[15]=k[17]=c[35]; k[11]=c[37]; k[13]=c[25];  k[19]=0;

/*** DECREMENT ***/
    overshoot-=carry;
    k[4]=c[24]; k[6]=k[12]=k[14]=c[32]; k[0]=k[8]=c[20]; k[2]=k[10]=c[22]; k[16]=k[18]=c[36];
    k[5]=c[25]; k[7]=k[13]=k[15]=c[33]; k[1]=k[9]=c[21]; k[3]=k[11]=c[23]; k[17]=k[19]=c[37];

/*** DECREMENT ***/
    overshoot-=carry;
    k[0]=k[6]=k[8]=c[26]; k[4]=k[10]=k[12]=c[30]; k[2]=k[14]=k[16]=k[18]=0;
    k[1]=k[7]=k[9]=c[27]; k[5]=k[11]=k[13]=c[31]; k[3]=k[15]=k[17]=k[19]=0;

/*** DECREMENT ***/
    overshoot-=carry;
    k[2]=k[8]=k[10]=c[28]; k[0]=k[4]=k[6]=k[16]=0; k[12]=k[14]=k[18]=c[38];
    k[3]=k[9]=k[11]=c[29]; k[1]=k[5]=k[7]=k[17]=0; k[13]=k[15]=k[19]=c[39];   
   
/*** DECREMENT ***/
    overshoot-=carry;

    b=modulus->w;
    while(overshoot>0)
    {
/*** DECREMENT ***/
        overshoot-=carry;
    }
    while (overshoot<0)
    {
/*** INCREMENT ***/
        overshoot+=carry;
    }

    if (z->w[MR_COMBA-1]>=modulus->w[MR_COMBA-1])
    {
        if (mr_compare(z,modulus)>=0)
        {
/*** DECREMENT ***/
        }
    }
    if (z->w[MR_COMBA-1]==0) mr_lzero(z);     

   #endif
#endif

#if MIRACL==16
   #if MR_COMBA==10

 /* 2^160-2^112+2^64+1 */ 

   a=t->w; b=k; c=z->w;
   k[0]=k[4]=a[19]; k[1]=k[2]=k[3]=k[5]=k[6]=0; k[7]=a[10]; k[8]=a[11]; k[9]=a[12]; 

/*** ADDITION ***/
    overshoot=carry;
    a=c; c=t->w;
    k[0]=k[1]=k[2]=k[3]=0; k[4]=k[7]=k[8]=c[17]; k[5]=c[18]; k[6]=c[12];  k[9]=0;

/*** DECREMENT ***/
    overshoot-=carry;
    k[2]=c[12]; k[3]=k[6]=k[7]=c[16]; k[0]=k[4]=c[10]; k[1]=k[5]=c[11]; k[8]=k[9]=c[18];

/*** DECREMENT ***/
    overshoot-=carry;
    k[0]=k[3]=k[4]=c[13]; k[2]=k[5]=k[6]=c[15]; k[1]=k[7]=k[8]=k[9]=0;

/*** DECREMENT ***/
    overshoot-=carry;
    k[1]=k[4]=k[5]=c[14]; k[0]=k[2]=k[3]=k[8]=0; k[6]=k[7]=k[9]=c[19];
    
/*** DECREMENT ***/
    overshoot-=carry;

    b=modulus->w;
    while(overshoot>0)
    {
/*** DECREMENT ***/
        overshoot-=carry;
    }
    while (overshoot<0)
    {
/*** INCREMENT ***/
        overshoot+=carry;
    }

    if (z->w[MR_COMBA-1]>=modulus->w[MR_COMBA-1])
    {
        if (mr_compare(z,modulus)>=0)
        {
/*** DECREMENT ***/
        }
    }
    if (z->w[MR_COMBA-1]==0) mr_lzero(z);
   #endif
#endif

#if MIRACL==32

#if MR_COMBA == 8
#ifdef MR_NOFULLWIDTH

/* Modulus is 2^255-19 - Experimental - not tested! */

w->w=&(t->w[10]);
w->len=9;
premult(_MIPP_ w,608,w);
incr(_MIPP_ w,19*(t->w[9]>>21),w);
t->w[9]&=(1<<21)-1;
t->len++;
z->len=10;
for (i=0;i<10;i++) z->w[i]=t->w[i];
comba_sub(z,w,z);


#endif
#endif

  #if MR_COMBA == 6

/* Special Code for 2^192-2^64-1 - assuming 32-bit processor */

    a=t->w; b=k; c=z->w;
    k[0]=k[2]=a[6]; k[1]=k[3]=a[7]; k[4]=k[5]=0; 
    
/*** ADDITION ***/
    overshoot=carry;  
    a=c;  c=t->w;
    k[0]=k[1]=0; k[2]=k[4]=c[8]; k[3]=k[5]=c[9];

/*** INCREMENT ***/
    overshoot+=carry;
    k[0]=k[2]=k[4]=c[10]; k[1]=k[3]=k[5]=c[11];
                       
/*** INCREMENT ***/
    overshoot+=carry;
    b=modulus->w;
    while(overshoot>0)
    {
/*** DECREMENT ***/
        overshoot-=carry;
    }
    if (z->w[MR_COMBA-1]>=modulus->w[MR_COMBA-1])
    {
        if (mr_compare(z,modulus)>=0)
        {
/*** DECREMENT ***/
        }
    }
    if (z->w[MR_COMBA-1]==0) mr_lzero(z);

  #endif

  #if MR_COMBA == 7
/* Special Code for 2^224-2^96+1 - assuming 32-bit processor */

    a=t->w; b=k; c=z->w;
    k[0]=k[1]=k[2]=0; k[3]=a[7]; k[4]=a[8]; k[5]=a[9]; k[6]=a[10];

/*** ADDITION ***/
    overshoot=carry;
    a=c; c=t->w;
    k[0]=k[1]=k[2]=k[6]=0; k[3]=c[11]; k[4]=c[12]; k[5]=c[13];

/*** INCREMENT ***/
    overshoot+=carry;
    k[0]=c[7]; k[1]=c[8]; k[2]=c[9]; k[3]=c[10]; k[4]=c[11]; k[5]=c[12]; k[6]=c[13];
    
/*** DECREMENT ***/
    overshoot-=carry;
    k[0]=c[11]; k[1]=c[12]; k[2]=c[13]; k[3]=k[4]=k[5]=k[6]=0;

/*** DECREMENT ***/
    overshoot-=carry;
    b=modulus->w;
    while (overshoot>0)
    {
/*** DECREMENT ***/
        overshoot-=carry;
    }
    while (overshoot<0)
    {
/*** INCREMENT ***/
        overshoot+=carry;
    }
    if (z->w[MR_COMBA-1]>=modulus->w[MR_COMBA-1])
    {
        if (mr_compare(z,modulus)>=0)
        {
/*** DECREMENT ***/
        }
    }
    if (z->w[MR_COMBA-1]==0) mr_lzero(z);

  #endif

  #if MR_COMBA == 8
    #ifndef MR_NOFULLWIDTH

    a=t->w; b=k; c=z->w;
    k[0]=k[1]=k[2]=0; k[3]=a[11]; k[4]=a[12]; k[5]=a[13]; k[6]=a[14]; k[7]=a[15];

/*** ADDITION ***/
    overshoot=carry;
    a=c; c=t->w;

/*** INCREMENT ***/
    overshoot+=carry;

    k[0]=k[1]=k[2]=0; k[3]=c[12]; k[4]=c[13]; k[5]=c[14]; k[6]=c[15]; k[7]=0;

/*** INCREMENT ***/
    overshoot+=carry;

/*** INCREMENT ***/
    overshoot+=carry;

    k[0]=c[8]; k[1]=c[9]; k[2]=c[10]; k[3]=k[4]=k[5]=0; k[6]=c[14]; k[7]=c[15];

/*** INCREMENT ***/
    overshoot+=carry;

    k[0]=c[9]; k[1]=c[10]; k[2]=c[11]; k[3]=c[13]; k[4]=c[14]; k[5]=c[15]; k[6]=c[13]; k[7]=c[8];

/*** INCREMENT ***/
    overshoot+=carry;

    k[0]=c[11]; k[1]=c[12]; k[2]=c[13]; k[3]=k[4]=k[5]=0; k[6]=c[8]; k[7]=c[10];

/*** DECREMENT ***/
    overshoot-=carry;

    k[0]=c[12]; k[1]=c[13]; k[2]=c[14]; k[3]=c[15]; k[4]=k[5]=0; k[6]=c[9]; k[7]=c[11];

/*** DECREMENT ***/
    overshoot-=carry;

    k[0]=c[13]; k[1]=c[14]; k[2]=c[15]; k[3]=c[8]; k[4]=c[9]; k[5]=c[10]; k[6]=0; k[7]=c[12];

/*** DECREMENT ***/
    overshoot-=carry;

    k[0]=c[14]; k[1]=c[15]; k[2]=0; k[3]=c[9]; k[4]=c[10]; k[5]=c[11]; k[6]=0; k[7]=c[13];

/*** DECREMENT ***/
    overshoot-=carry;

    b=modulus->w;
    while (overshoot>0)
    {
/*** DECREMENT ***/
        overshoot-=carry;
    }
    while (overshoot<0)
    {
/*** INCREMENT ***/
        overshoot+=carry;
    }
    if (z->w[MR_COMBA-1]>=modulus->w[MR_COMBA-1])
    {
        if (compare(z,modulus)>=0)
        {
/*** DECREMENT ***/
        }
    }
    if (z->w[MR_COMBA-1]==0) mr_lzero(z);

    #endif
  #endif

  #if MR_COMBA == 17

/* Special Code for 2^521-1 - assuming 32-bit processor */

/* split t into 521-bit halves, low half in a, high half in b */

    a=t->w; b=k; c=z->w;

    for (i=0;i<=16;i++)
        b[i]=(a[i+16]>>9)|(a[i+17]<<23);

    b[16]|=(-(a[16]>>9)<<9); /* clever stuff! Set top part of b[16] to minus  *
                              * top part of a[16]. When added they cancel out */

/*** ADDITION ***/
                             /* ignore carry=1 */
    a=z->w;                   
    b=modulus->w;

    if (z->w[MR_COMBA-1]>=modulus->w[MR_COMBA-1])
    {
        if (mr_compare(z,modulus)>=0)
        {
/*** DECREMENT ***/
        }
    }
    if (z->w[MR_COMBA-1]==0) mr_lzero(z);
  #endif
  #endif
  #endif
#else
    modulus=mr_mip->modulus;  
    ndash=mr_mip->ndash;
    w=mr_mip->w0;
    if (t!=w) copy(t,w);       
    w->len=2*MR_COMBA+1;
    a=w->w; b=modulus->w;

/*** REDC ***/      /* reduces a mod b */
    
    for (i=MR_COMBA;i<(int)(z->len&MR_OBITS);i++) z->w[i]=0;
   
    z->len=MR_COMBA;
    for (i=0;i<MR_COMBA;i++) z->w[i]=w->w[i+MR_COMBA];

    need_subtract=FALSE;

    if (w->w[MR_COMBA+MR_COMBA]!=0)
    {
        need_subtract=TRUE;
    }
    else 
    {
        if (z->w[MR_COMBA-1]!=0)
        {
            if (z->w[MR_COMBA-1]>modulus->w[MR_COMBA-1]) need_subtract=TRUE;
            else
            {
                if (z->w[MR_COMBA-1]==modulus->w[MR_COMBA-1])
                {
                    if (mr_compare(z,modulus)>=0) need_subtract=TRUE;
                }
            }
        }
        else mr_lzero(z);
    }

    if (need_subtract)
    {
        a=z->w; b=modulus->w;
/*** DECREMENT ***/    
	z->len=MR_COMBA;
        if (z->w[MR_COMBA-1]==0) mr_lzero(z);
    }

#endif
} 

void comba_add(_MIPD_ big x,big y,big w)
{ /* fast modular addition */
    unsigned int i;
    big modulus;
    BOOL dodec;
    mr_small *a,*b,*c;
    mr_small carry,su;  
#ifdef MR_ITANIUM
    mr_small ma,u;
#endif
#ifdef MR_NOASM
    mr_large u;
#endif
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    modulus=mr_mip->modulus;
    if (w!=x && w!=y) 
    {
        for (i=MR_COMBA;i<(w->len&MR_OBITS);i++) w->w[i]=0;
        /* zero(w); */
    }
    
    a=x->w; b=y->w; c=w->w;
/*** ADDITION ***/        /* add a and b, result in c */
    w->len=MR_COMBA;

/* if sum is greater than modulus a decrement will be required */

    dodec=FALSE;
    if (carry) dodec=TRUE;  /* possible misprediction here */
    else
    {
        if (w->w[MR_COMBA-1]>modulus->w[MR_COMBA-1]) dodec=TRUE; /* possible misprediction here */
	else
	{
            if (w->w[MR_COMBA-1]==modulus->w[MR_COMBA-1]) /* this will be very rare, so easily predicted */
	    { /* trying to avoid calling this slow function */
	        if (mr_compare(w,modulus)>=0) dodec=TRUE; /* do full comparison */
	    }
        }
    }

    if (dodec)  /* prediction here correlated to earlier predictions, so should predict nicely */
    {
        a=w->w; b=modulus->w;
/*** DECREMENT ***/        /* decrement b from a */
    }
    if (w->w[MR_COMBA-1]==0) mr_lzero(w);   

}

#ifndef MR_NO_LAZY_REDUCTION

void comba_double_add(_MIPD_ big x,big y,big w)
{ /* fast modular addition */
    unsigned int i;
    big modulus;
    BOOL dodec;
    mr_small *a,*b,*c;
    mr_small carry,su;  
#ifdef MR_ITANIUM
    mr_small ma,u;
#endif
#ifdef MR_NOASM
    mr_large u;
#endif
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    modulus=mr_mip->pR;
    if (w!=x && w!=y) 
    {
        for (i=2*MR_COMBA;i<(w->len&MR_OBITS);i++) w->w[i]=0;
        /* zero(w); */
    }
    
    a=x->w; b=y->w; c=w->w;
/*** ADDITION2 ***/        /* add a and b, result in c */
    w->len=2*MR_COMBA;

/* if sum is greater than modulus a decrement will be required */

    dodec=FALSE;
    if (carry) dodec=TRUE;  /* possible misprediction here */
    else
    {
        if (w->w[2*MR_COMBA-1]>modulus->w[2*MR_COMBA-1]) dodec=TRUE; /* possible misprediction here */
	else
	{
            if (w->w[2*MR_COMBA-1]==modulus->w[2*MR_COMBA-1]) /* this will be very rare, so easily predicted */
	    {
	        if (mr_compare(w,modulus)>=0) dodec=TRUE; /* do full comparison */
	    }
	}
    }

    if (dodec)  /* prediction here correlated to earlier predictions, so should predict nicely */
    {
         a=&(w->w[MR_COMBA]); b=&(modulus->w[MR_COMBA]);
/*** DECREMENT ***/        /* decrement b from a */
    }
    if (w->w[2*MR_COMBA-1]==0) mr_lzero(w);   

}

#endif

void comba_sub(_MIPD_ big x,big y,big w)
{ /* fast modular subtraction */
    unsigned int i;
    big modulus;
    mr_small *a,*b,*c;
    mr_small carry,su;  
#ifdef MR_ITANIUM
    mr_small ma,u;
#endif
#ifdef MR_NOASM
    mr_large u;
#endif

#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    modulus=mr_mip->modulus;
    if (x!=w && y!=w) 
    {
        for (i=MR_COMBA;i<(w->len&MR_OBITS);i++) w->w[i]=0;   
        /* zero(w); */
    }

    a=x->w; b=y->w; c=w->w;
/*** SUBTRACTION ***/

    if (carry)
    {
        a=w->w; b=modulus->w; 
/*** INCREMENT ***/        /* add a and b, result in c */
    
    }
    w->len=MR_COMBA;
    if (w->w[MR_COMBA-1]==0) mr_lzero(w); 
}

#ifndef MR_NO_LAZY_REDUCTION

void comba_double_sub(_MIPD_ big x,big y,big w)
{ /* fast modular subtraction */
    unsigned int i;
    big modulus;
    mr_small *a,*b,*c;
    mr_small carry,su;  
#ifdef MR_ITANIUM
    mr_small ma,u;
#endif
#ifdef MR_NOASM
    mr_large u;
#endif

#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    modulus=mr_mip->modulus;
    if (x!=w && y!=w) 
    {
        for (i=2*MR_COMBA;i<(w->len&MR_OBITS);i++) w->w[i]=0;   
        /* zero(w); */
    }

    a=x->w; b=y->w; c=w->w;
/*** SUBTRACTION2 ***/

    if (carry)
    {
        a=&(w->w[MR_COMBA]); b=modulus->w; 
/*** INCREMENT ***/        /* add a and b, result in c */
    
    }
    w->len=2*MR_COMBA;
    if (w->w[2*MR_COMBA-1]==0) mr_lzero(w); 
}

#endif

void comba_negate(_MIPD_ big x,big w)
{ /* fast modular subtraction */
    unsigned int i;
    big modulus;
    mr_small *a,*b,*c;
    mr_small carry,su;  
#ifdef MR_ITANIUM
    mr_small ma,u;
#endif
#ifdef MR_NOASM
    mr_large u;
#endif

#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    modulus=mr_mip->modulus;
    if (w!=x) 
    {
        for (i=MR_COMBA;i<(w->len&MR_OBITS);i++) w->w[i]=0;
        /* zero(w); */
    }
    a=modulus->w; b=x->w; c=w->w;

/*** SUBTRACTION ***/

    w->len=MR_COMBA;
    if (w->w[MR_COMBA-1]==0) mr_lzero(w); 
}

#endif
