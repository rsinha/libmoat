/*
 *   MIRACL Jacobi symbol routine
 *   mrjack.c
 *
 *   See "Efficient Algorithms for Computing the Jacobi Symbol"
 *   Meyer & Sorenson
 *
 *   Copyright (c) 2007 Shamus Software Ltd.
 */

#include "miracl.h"

#ifdef MR_FP
#include <math.h>
#endif

static void rfind(mr_small u,mr_small v,mr_small k,mr_small sk,mr_utype *a,mr_utype *b)
{
    mr_utype x2,y2,r;
    mr_small w,q,x1,y1,sr;
#ifdef MR_FP
    mr_small dres;
#endif

    w=invers(v,k);
    w=smul(u,w,k);
    
    x1=k; x2=0;
    y1=w; y2=1;

/* NOTE: x1 and y1 are always +ve. x2 and y2 are always small */

    while (y1>=sk)
    {
#ifndef MR_NOFULLWIDTH
        if (x1==0) q=muldvm((mr_small)1,(mr_small)0,y1,&sr);
        else 
#endif
        q=MR_DIV(x1,y1);
        r= x1-q*y1; x1=y1; y1=r;
        sr=x2-q*y2; x2=y2; y2=sr;
    }
    if (y2>=0) { *a=y2;  *b=0-y1; }
    else       { *a=-y2; *b=y1;  }
}

int jack(_MIPD_ big U,big V)
{ /* find jacobi symbol for U wrt V. Only defined for *
   * positive V, V odd. Otherwise returns 0           */
    int i,e,r,m,t,v8,u4;
    mr_utype a,b;
    mr_small u,v,d,g,k,sk,s;
#ifdef MR_FP
    mr_small dres;
#endif
    big w;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
#ifdef MR_FP_ROUNDING
    mr_large ik,id;
#endif
    if (mr_mip->ERNUM || size(U)==0 || size(V) <1) return 0;
    copy(U,mr_mip->w1);
    copy(V,mr_mip->w2);
    a=0;
    MR_IN(3)

    if (remain(_MIPP_ mr_mip->w2,2)==0)
    { /* V is even */
        MR_OUT
        return 0;
    }

    if (mr_mip->base!=0)
    {
        k=1;
        for (m=1;;m++)
        {
           k*=2;
           if (k==MAXBASE) break;
        }    
        if (m%2==1) {m--; k=MR_DIV(k,2);}
#ifdef MR_FP_ROUNDING
        ik=mr_invert(k);
#endif
    }
    else
    {
        m=MIRACL;
        k=0;
    }
    r=m/2;
    sk=1;
    for (i=0;i<r;i++) sk*=2;

    t=1;
    v8=remain(_MIPP_ mr_mip->w2,8); 

    while (!mr_mip->ERNUM && size(mr_mip->w1)!=0)
    {
        if (size(mr_mip->w1)<0)
        {
            negify(mr_mip->w1,mr_mip->w1);
            if (v8%4==3) t=-t;
        }

        do { /* oddify */

#ifndef MR_ALWAYS_BINARY
            if (mr_mip->base==mr_mip->base2) 
            {
#endif
                 if (mr_mip->base==k) u=mr_mip->w1->w[0];
                 else                 u=MR_REMAIN(mr_mip->w1->w[0],k); 
#ifndef MR_ALWAYS_BINARY
            }

#ifdef MR_FP_ROUNDING
            else u=mr_sdiv(_MIPP_ mr_mip->w1,k,ik,mr_mip->w3);
#else
            else u=mr_sdiv(_MIPP_ mr_mip->w1,k,mr_mip->w3);
#endif

#endif
            if (u==0) {s=k; e=0;}
            else
            {
                s=1; e=0;
                while (MR_REMAIN(u,2)==0) {s*=2; e++; u=MR_DIV(u,2);}
            }
            if (s==mr_mip->base) mr_shift(_MIPP_ mr_mip->w1,-1,mr_mip->w1);
#ifdef MR_FP_ROUNDING
            else if (s>1) 
            { 
                mr_sdiv(_MIPP_ mr_mip->w1,s,mr_invert(s),mr_mip->w1);
            }
#else
            else if (s>1) mr_sdiv(_MIPP_ mr_mip->w1,s,mr_mip->w1);
#endif
        } while (u==0);
        if (e%2!=0 && (v8==3 || v8==5)) t=-t;
        if (mr_compare(mr_mip->w1,mr_mip->w2)<0)
        {
            if (mr_mip->base==mr_mip->base2) u4=(int)MR_REMAIN(mr_mip->w1->w[0],4);
            else                             u4=remain(_MIPP_ mr_mip->w1,4);
            if (v8%4==3 && u4==3) t=-t; 
            w=mr_mip->w1; mr_mip->w1=mr_mip->w2; mr_mip->w2=w;
        }

#ifndef MR_ALWAYS_BINARY
        if (mr_mip->base==mr_mip->base2)
        {
#endif
            if (k==mr_mip->base)   
            {
                u=mr_mip->w1->w[0];
                v=mr_mip->w2->w[0];
            }
            else
            {
                u=MR_REMAIN(mr_mip->w1->w[0],k);
                v=MR_REMAIN(mr_mip->w2->w[0],k);
            }
#ifndef MR_ALWAYS_BINARY
        }
        else
        {
#ifdef MR_FP_ROUNDING
            u=mr_sdiv(_MIPP_ mr_mip->w1,k,ik,mr_mip->w3);
            v=mr_sdiv(_MIPP_ mr_mip->w2,k,ik,mr_mip->w3);
#else
            u=mr_sdiv(_MIPP_ mr_mip->w1,k,mr_mip->w3);
            v=mr_sdiv(_MIPP_ mr_mip->w2,k,mr_mip->w3);
#endif
        }
#endif
        rfind(u,v,k,sk,&a,&b);
        if (a>1)
        {
#ifdef MR_FP_ROUNDING
            d=mr_sdiv(_MIPP_ mr_mip->w2,a,mr_invert(a),mr_mip->w3);
#else
            d=mr_sdiv(_MIPP_ mr_mip->w2,a,mr_mip->w3);
#endif
            d=sgcd(d,a);
            a=MR_DIV(a,d); 
        }
        else d=1;

        if (d>1) 
        {
#ifdef MR_FP_ROUNDING
            id=mr_invert(d);
            mr_sdiv(_MIPP_ mr_mip->w2,d,id,mr_mip->w2);
            u=mr_sdiv(_MIPP_ mr_mip->w1,d,id,mr_mip->w3);
#else
            mr_sdiv(_MIPP_ mr_mip->w2,d,mr_mip->w2);
            u=mr_sdiv(_MIPP_ mr_mip->w1,d,mr_mip->w3);
#endif
        }
        else u=0;   

        g=a;
        if (mr_mip->base==mr_mip->base2) v8=(int)MR_REMAIN(mr_mip->w2->w[0],8);
        else                             v8=remain(_MIPP_ mr_mip->w2,8);
        while (MR_REMAIN(g,2)==0)
        {
            g=MR_DIV(g,2);
            if (v8==3 || v8==5) t=-t;
        }
        if (MR_REMAIN(g,4)==3 && v8%4==3) t=-t;
#ifdef MR_FP_ROUNDING
        v=mr_sdiv(_MIPP_ mr_mip->w2,g,mr_invert(g),mr_mip->w3);
#else
        v=mr_sdiv(_MIPP_ mr_mip->w2,g,mr_mip->w3);
#endif
        t*=jac(v,g)*jac(u,d);
        if (t==0) 
        {
            MR_OUT
            return 0;
        }

/* printf("a= %I64d b=%I64d %d\n",a,b,(int)b); */

        if (a>1) mr_pmul(_MIPP_ mr_mip->w1,a,mr_mip->w1);
        if (b>=0)
            mr_pmul(_MIPP_ mr_mip->w2,b,mr_mip->w3);
        else
        {
            b=-b;
            mr_pmul(_MIPP_ mr_mip->w2,b,mr_mip->w3);
            negify(mr_mip->w3,mr_mip->w3);
        }
       /* premult(_MIPP_ mr_mip->w2,(int)b,mr_mip->w3); <- nasty bug - potential loss of precision in b */
        add(_MIPP_ mr_mip->w1,mr_mip->w3,mr_mip->w1);
        if (k==mr_mip->base) mr_shift(_MIPP_ mr_mip->w1,-1,mr_mip->w1);
#ifdef MR_FP_ROUNDING
        else                 mr_sdiv(_MIPP_ mr_mip->w1,k,ik,mr_mip->w1);
#else
        else                 mr_sdiv(_MIPP_ mr_mip->w1,k,mr_mip->w1);
#endif
    }
    MR_OUT
    if (size(mr_mip->w2)==1) return t;
    return 0; 
} 

