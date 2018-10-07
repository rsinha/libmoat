/*
 *   MIRACL method for modular square root
 *   mrsroot.c 
 *
 *   Siguna Mueller's O(lg(p)^3) algorithm, Designs Codes and Cryptography, 2004 
 * 
 *   This is a little slower for p=3 mod 4 primes, but its not time critical, and
 *   more importantly it doesn't pull in the large powmod code into elliptic curve programs
 *   It does require code from mrjack.c, mrlucas.c and mrsmall.c
 *
 *   If p=3 mod 4, then  sqrt(a) = V_{(p+1)/4}(a+1/a,1)/(1+1/a)
 *
 *   Its also very simple, uses very little memory, and it works just fine for p=1 mod 8 primes
 *   (for example the "annoying" NIST modulus 2^224-2^96+1)
 *   Also doesn't waste time on non-squares, as a jacobi test is done first
 *
 *   If you know that the prime is 3 mod 4, and you know that x is almost certainly a QR
 *   then the jacobi-dependent code can be deleted with some space savings.
 * 
 *   Copyright (c) 2007 Shamus Software Ltd.
 */

#include <stdlib.h>
#include "miracl.h"

BOOL nres_sqroot(_MIPD_ big x,big w)
{ /* w=sqrt(x) mod p. This depends on p being prime! */
    int t,js;
   
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return FALSE;

    zero(w);
    if (size(x)==0) return TRUE;  /* yes square root of 0 is zero */
    redc(_MIPP_ x,mr_mip->w15);   /* get it back into normal form */
 
/* Jacobi test. Could be eliminated if we are pretty sure that x is a QR */    

    if (jack(_MIPP_ mr_mip->w15,mr_mip->modulus)!=1) return FALSE;

    MR_IN(100)
    
    if (size(mr_mip->w15)==1) /* square root of 1 is 1 */
    {
        convert(_MIPP_ 1,w);
        nres(_MIPP_ w,w);
        MR_OUT
        return TRUE;
    }

    if (size(mr_mip->w15)==4) /* square root of 4 is 2 */
    {
        convert(_MIPP_ 2,w);
        nres(_MIPP_ w,w);
        MR_OUT
        return TRUE;
    }

    js=mr_mip->pmod8%4-2;     /* 1 mod 4 or 3 mod 4 prime? */

    incr(_MIPP_ mr_mip->modulus,js,mr_mip->w14);
    subdiv(_MIPP_ mr_mip->w14,4,mr_mip->w14);    /* (p+/-1)/4 */

    if (js==1)
    { /* 3 mod 4 primes */
        convert(_MIPP_ 1,mr_mip->w10);
        nres(_MIPP_ mr_mip->w10,mr_mip->w10);  /* w10=1 */
        nres(_MIPP_ mr_mip->w15,mr_mip->w15);
        nres_moddiv(_MIPP_ mr_mip->w10,mr_mip->w15,mr_mip->w11); /* w11 = 1/a */
        nres_modadd(_MIPP_ mr_mip->w11,mr_mip->w15,mr_mip->w3);  /* 1/a + a   */
        nres_lucas(_MIPP_ mr_mip->w3,mr_mip->w14,w,w);
        nres_modadd(_MIPP_ mr_mip->w11,mr_mip->w10,mr_mip->w11);  /* 1+1/a    */
        nres_moddiv(_MIPP_ w,mr_mip->w11,w);
    } 
    else
    { /* 1 mod 4 primes */
        for (t=1; ;t++)
        { /* t=1.5 on average */
            if (t==1) copy(mr_mip->w15,mr_mip->w4);
            else
            {
                premult(_MIPP_ mr_mip->w15,t,mr_mip->w4);
                divide(_MIPP_ mr_mip->w4,mr_mip->modulus,mr_mip->modulus);
                premult(_MIPP_ mr_mip->w4,t,mr_mip->w4);
                divide(_MIPP_ mr_mip->w4,mr_mip->modulus,mr_mip->modulus);
            }

            decr(_MIPP_ mr_mip->w4,4,mr_mip->w1);
            if (jack(_MIPP_ mr_mip->w1,mr_mip->modulus)==js) break;
            if (mr_mip->ERNUM) break;
        }
    
        decr(_MIPP_ mr_mip->w4,2,mr_mip->w3);
        nres(_MIPP_ mr_mip->w3,mr_mip->w3);
        nres_lucas(_MIPP_ mr_mip->w3,mr_mip->w14,w,w); /* heavy lifting done here */
        if (t!=1)
        {
            convert(_MIPP_ t,mr_mip->w8);
            nres(_MIPP_ mr_mip->w8,mr_mip->w8);
            nres_moddiv(_MIPP_ w,mr_mip->w8,w);
        }
        nres(_MIPP_ mr_mip->w15,mr_mip->w15);
    }

    nres_modmult(_MIPP_ w,w,mr_mip->w14);  /* check result */
    
    MR_OUT
    if (mr_compare(mr_mip->w14,mr_mip->w15)==0) 
        return TRUE;
    zero(w);
    return FALSE;
 }

BOOL sqroot(_MIPD_ big x,big p,big w)
{ /* w = sqrt(x) mod p */
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return FALSE;

    MR_IN(101)

    if (subdivisible(_MIPP_ p,2))
    { /* p must be odd */
        zero(w);
        MR_OUT
        return FALSE;
    }

    prepare_monty(_MIPP_ p);
    nres(_MIPP_ x,mr_mip->w15);
    if (nres_sqroot(_MIPP_ mr_mip->w15,w))
    {
        redc(_MIPP_ w,w);
        MR_OUT
        return TRUE;
    }

    zero(w);
    MR_OUT
    return FALSE;
}
