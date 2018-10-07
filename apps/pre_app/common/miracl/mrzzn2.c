/*
 *   MIRACL F_p^2 support functions 
 *   mrzzn2.c
 *
 *   Copyright (c) 2006 Shamus Software Ltd.
 */

#include <stdlib.h> 
#include "miracl.h"

BOOL zzn2_iszero(zzn2 *x)
{
    if (size(x->a)==0 && size(x->b)==0) return TRUE;
    return FALSE;
}

BOOL zzn2_isunity(_MIPD_ zzn2 *x)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM || size(x->b)!=0) return FALSE;
    MR_IN(155)

    redc(_MIPP_ x->a,mr_mip->w1);

    MR_OUT
    if (size(mr_mip->w1)==1) return TRUE;
    return FALSE;
}

BOOL zzn2_compare(zzn2 *x,zzn2 *y)
{
    if (mr_compare(x->a,y->a)==0 && mr_compare(x->b,y->b)==0) return TRUE;
    return FALSE;
}

void zzn2_from_int(_MIPD_ int i,zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(156)
    convert(_MIPP_ i,mr_mip->w1);
    nres(_MIPP_ mr_mip->w1,w->a);
    zero(w->b);
    MR_OUT
}

void zzn2_from_ints(_MIPD_ int i,int j,zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(168)
    convert(_MIPP_ i,mr_mip->w1);
    nres(_MIPP_ mr_mip->w1,w->a);
    convert(_MIPP_ j,mr_mip->w1);
    nres(_MIPP_ mr_mip->w1,w->b);

    MR_OUT
}

void zzn2_from_zzns(big x,big y,zzn2 *w)
{
    copy(x,w->a);
    copy(y,w->b);
}

void zzn2_from_bigs(_MIPD_ big x,big y, zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(166)
    nres(_MIPP_ x,w->a);
    nres(_MIPP_ y,w->b);
    MR_OUT
}

void zzn2_from_zzn(big x,zzn2 *w)
{
    copy(x,w->a);
    zero(w->b);
}

void zzn2_from_big(_MIPD_ big x, zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(167)
    nres(_MIPP_ x,w->a);
    zero(w->b);
    MR_OUT
}

void zzn2_copy(zzn2 *x,zzn2 *w)
{
    if (x==w) return;
    copy(x->a,w->a);
    copy(x->b,w->b);
}

void zzn2_zero(zzn2 *w)
{
    zero(w->a);
    zero(w->b);
}

void zzn2_negate(_MIPD_ zzn2 *x,zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    MR_IN(157)
    zzn2_copy(x,w);
    nres_negate(_MIPP_ w->a,w->a);
    nres_negate(_MIPP_ w->b,w->b);
    MR_OUT
}

void zzn2_conj(_MIPD_ zzn2 *x,zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    MR_IN(158)
    if (mr_mip->ERNUM) return;
    zzn2_copy(x,w);
    nres_negate(_MIPP_ w->b,w->b);
    MR_OUT
}

void zzn2_add(_MIPD_ zzn2 *x,zzn2 *y,zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    MR_IN(159)
    if (mr_mip->ERNUM) return;
    nres_modadd(_MIPP_ x->a,y->a,w->a);
    nres_modadd(_MIPP_ x->b,y->b,w->b);
    MR_OUT
}
  
void zzn2_sadd(_MIPD_ zzn2 *x,big y,zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    MR_IN(169)
    if (mr_mip->ERNUM) return;
    nres_modadd(_MIPP_ x->a,y,w->a);
    MR_OUT
}              

void zzn2_sub(_MIPD_ zzn2 *x,zzn2 *y,zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    MR_IN(160)
    nres_modsub(_MIPP_ x->a,y->a,w->a);
    nres_modsub(_MIPP_ x->b,y->b,w->b);
    MR_OUT
}

void zzn2_ssub(_MIPD_ zzn2 *x,big y,zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    MR_IN(170)
    nres_modsub(_MIPP_ x->a,y,w->a);
    MR_OUT
}

void zzn2_smul(_MIPD_ zzn2 *x,big y,zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    MR_IN(161)
    if (size(x->a)!=0) nres_modmult(_MIPP_ x->a,y,w->a);
    else zero(w->a);
    if (size(x->b)!=0) nres_modmult(_MIPP_ x->b,y,w->b);
    else zero(w->b);
    MR_OUT
}

void zzn2_imul(_MIPD_ zzn2 *x,int y,zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    MR_IN(152)
    if (size(x->a)!=0) nres_premult(_MIPP_ x->a,y,w->a);
    else zero(w->a);
    if (size(x->b)!=0) nres_premult(_MIPP_ x->b,y,w->b);
    else zero(w->b);
    MR_OUT
}

void zzn2_mul(_MIPD_ zzn2 *x,zzn2 *y,zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

    if (mr_mip->ERNUM) return;
    MR_IN(162)
    if (x==y)
    {
        nres_modadd(_MIPP_ x->a,x->b,mr_mip->w1);
        nres_modsub(_MIPP_ x->a,x->b,mr_mip->w2);

        if (mr_mip->qnr==-2)
            nres_modsub(_MIPP_ mr_mip->w2,x->b,mr_mip->w2);
       
        nres_modmult(_MIPP_ x->a,x->b,w->b);
        nres_modmult(_MIPP_ mr_mip->w1,mr_mip->w2,w->a);

        if (mr_mip->qnr==-2)
            nres_modadd(_MIPP_ w->a,w->b,w->a);

        nres_modadd(_MIPP_ w->b,w->b,w->b);
    }
    else
    { /* Uses w1, w2, w5, w6 and possibly w7 */
        if (zzn2_iszero(x) || zzn2_iszero(y)) zzn2_zero(w);
        else
        {
#ifndef MR_NO_LAZY_REDUCTION 
            if (x->a->len!=0 && x->b->len!=0 && y->a->len!=0 && y->b->len!=0)
                nres_lazy(_MIPP_ x->a,x->b,y->a,y->b,w->a,w->b);
            else
            {
#endif
                nres_modmult(_MIPP_ x->a,y->a,mr_mip->w1);
                nres_modmult(_MIPP_ x->b,y->b,mr_mip->w2);
                nres_modadd(_MIPP_ x->a,x->b,mr_mip->w5);
                nres_modadd(_MIPP_ y->a,y->b,w->b);
                nres_modmult(_MIPP_ w->b,mr_mip->w5,w->b);
                nres_modsub(_MIPP_ w->b,mr_mip->w1,w->b);
                nres_modsub(_MIPP_ w->b,mr_mip->w2,w->b);
                nres_modsub(_MIPP_ mr_mip->w1,mr_mip->w2,w->a);
                if (mr_mip->qnr==-2)
                    nres_modsub(_MIPP_ w->a,mr_mip->w2,w->a);
#ifndef MR_NO_LAZY_REDUCTION
            }
#endif
        }
    }    
    MR_OUT
}

void zzn2_inv(_MIPD_ zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    MR_IN(163)
    nres_modmult(_MIPP_ w->a,w->a,mr_mip->w1); 
    nres_modmult(_MIPP_ w->b,w->b,mr_mip->w2); 
    nres_modadd(_MIPP_ mr_mip->w1,mr_mip->w2,mr_mip->w1);

    if (mr_mip->qnr==-2)
        nres_modadd(_MIPP_ mr_mip->w1,mr_mip->w2,mr_mip->w1);

    redc(_MIPP_ mr_mip->w1,mr_mip->w6);
    xgcd(_MIPP_ mr_mip->w6,mr_mip->modulus,mr_mip->w6,mr_mip->w6,mr_mip->w6);
    nres(_MIPP_ mr_mip->w6,mr_mip->w6);

    nres_modmult(_MIPP_ w->a,mr_mip->w6,w->a);
    nres_negate(_MIPP_ mr_mip->w6,mr_mip->w6);
    nres_modmult(_MIPP_ w->b,mr_mip->w6,w->b);
    MR_OUT
}

/* divide zzn2 by 2 */

void zzn2_div2(_MIPD_ zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    MR_IN(173)
    copy(w->a,mr_mip->w1);
    if (remain(_MIPP_ mr_mip->w1,2)!=0)
        add(_MIPP_ mr_mip->w1,mr_mip->modulus,mr_mip->w1);
    subdiv(_MIPP_ mr_mip->w1,2,mr_mip->w1);
    copy(mr_mip->w1,w->a);

    copy(w->b,mr_mip->w1);
    if (remain(_MIPP_ mr_mip->w1,2)!=0)
        add(_MIPP_ mr_mip->w1,mr_mip->modulus,mr_mip->w1);
    subdiv(_MIPP_ mr_mip->w1,2,mr_mip->w1);
    copy(mr_mip->w1,w->b);
    MR_OUT
}

/* multiply zzn2 by i */

void zzn2_timesi(_MIPD_ zzn2 *u)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;
    MR_IN(164)
    copy(u->a,mr_mip->w1);
    nres_negate(_MIPP_ u->b,u->a);
    if (mr_mip->qnr==-2)
        nres_modadd(_MIPP_ u->a,u->a,u->a);

    copy(mr_mip->w1,u->b);
    MR_OUT
}

/* Lucas-style ladder exponentiation - for ZZn4 exponentiation 

void zzn2_powl(_MIPD_ zzn2 *x,big e,zzn2 *w)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    int i,s;
    zzn2 t1,t3,t4;
    if (mr_mip->ERNUM) return;
    MR_IN(165)
    t1.a=mr_mip->w3;
    t1.b=mr_mip->w4;
    t3.a=mr_mip->w8;
    t3.b=mr_mip->w9;
    t4.a=mr_mip->w10;
    t4.b=mr_mip->w11;

    zzn2_from_int(_MIPP_ 1,&t1);

    s=size(e);
    if (s==0)
    {
        zzn2_copy(&t1,w);
        return;
    }
    zzn2_copy(x,w);
    if (s==1 || s==(-1)) return;

    i=logb2(_MIPP_ e)-1;

    zzn2_copy(w,&t3);
    zzn2_mul(_MIPP_ w,w,&t4);
    zzn2_add(_MIPP_ &t4,&t4,&t4);
    zzn2_sub(_MIPP_ &t4,&t1,&t4);

    while (i-- && !mr_mip->ERNUM)
    {
        if (mr_testbit(_MIPP_ e,i))
        {
            zzn2_mul(_MIPP_ &t3,&t4,&t3);
            zzn2_add(_MIPP_ &t3,&t3,&t3);
            zzn2_sub(_MIPP_ &t3,w,&t3);
            zzn2_mul(_MIPP_ &t4,&t4,&t4);
            zzn2_add(_MIPP_ &t4,&t4,&t4);
            zzn2_sub(_MIPP_ &t4,&t1,&t4);
        }
        else
        {
            zzn2_mul(_MIPP_ &t4,&t3,&t4);
            zzn2_add(_MIPP_ &t4,&t4,&t4);
            zzn2_sub(_MIPP_ &t4,w,&t4);
            zzn2_mul(_MIPP_ &t3,&t3,&t3);
            zzn2_add(_MIPP_ &t3,&t3,&t3);
            zzn2_sub(_MIPP_ &t3,&t1,&t3);
        }

    }
    zzn2_copy(&t4,w);
    MR_OUT
}
*/
