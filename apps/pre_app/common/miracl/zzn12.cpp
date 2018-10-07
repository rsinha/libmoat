/*
 *    MIRACL  C++ Implementation file zzn12.cpp
 *
 *    AUTHOR  : M. Scott
 *  
 *    PURPOSE : Implementation of class ZZn12  (Arithmetic over n^12)
 *
 * WARNING: This class has been cobbled together for a specific use with
 * the MIRACL library. It is not complete, and may not work in other 
 * applications
 *
 *    NOTE: - The irreducible polynomial is assumed to be of the form 
 *            x^6+i, where i is either 
 *      sqrt(-1) or 1+sqrt(-1) if p=3 mod 8
 *   or sqrt(-2), 1+sqrt(-2) if p=5 mod 8 or 7 mod 8
 *
 *    Copyright (c) 2006 Shamus Software Ltd.
 */

#include "zzn12.h"

using namespace std;

// Frobenius...

ZZn12& ZZn12::powq(const ZZn12& X)
{
    ZZn6 W=real(X*X);
    *this=a.powq(W)+X*b.powq(W);
    return *this;
}

void ZZn12::get(ZZn6 &x,ZZn6 &y)  
{x=a; y=b; } 

void ZZn12::get(ZZn6& x) 
{x=a; }

ZZn12& ZZn12::operator*=(const ZZn12& x)
{ 
    if (&x==this)
    {  
        ZZn6 t=a; t+=b;
        ZZn6 t2=a; t2+=tx(b);
        t*=t2;
        b*=a;
        t-=b;
        t-=tx(b);
        b+=b;
        a=t;  
    }
    else
    { // Karatsuba multiplication
        ZZn6 ac=a; ac*=x.a;
        ZZn6 bd=b; bd*=x.b;
        ZZn6 t=x.a; t+=x.b;
        b+=a; b*=t; b-=ac; b-=bd;
        a=ac; a+=tx(bd);
    }

    return *this;
}

ZZn12 conj(const ZZn12& x)
{
    ZZn12 u=x;
    u.conj();
    return u;
}

ZZn12 inverse(const ZZn12 &w)
{
    ZZn12 y=conj(w);
    ZZn6 u=w.a;
    ZZn6 v=w.b;
    u*=u;
    v*=v;
    u-=tx(v);
    u=inverse(u);
    y*=u;
    return y;
}

ZZn12& ZZn12::operator/=(const ZZn12& x)
{ // inversion 
 *this *= inverse(x);
 return *this;
}

ZZn12 operator+(const ZZn12& x,const ZZn12& y) 
{ZZn12 w=x; w.a+=y.a; w.b+=y.b; return w;} 

ZZn12 operator+(const ZZn12& x,const ZZn6& y) 
{ZZn12 w=x; w.a+=y; return w; } //

ZZn12 operator-(const ZZn12& x,const ZZn12& y) 
{ZZn12 w=x; w.a-=y.a; w.b-=y.b; return w; } 

ZZn12 operator-(const ZZn12& x,const ZZn6& y) 
{ZZn12 w=x; w.a-=y; return w; } //

ZZn12 operator-(const ZZn12& x) 
{ZZn12 w; w.a=-x.a; w.b=-x.b; return w; } 

ZZn12 operator*(const ZZn12& x,const ZZn12& y)
{
    ZZn12 w=x;
    if (&x==&y) w*=w;
    else        w*=y;    
    return w;
}

ZZn12 operator*(const ZZn12& x,const ZZn6& y)
{ZZn12 w=x; w.a*=y; w.b*=y; return w;} //

ZZn12 operator*(const ZZn6& y,const ZZn12& x)
{ZZn12 w=x; w.a*=y; w.b*=y; return w;} //

ZZn12 operator*(const ZZn12& x,int y)
{ZZn12 w=x; w.a*=y; w.b*=y; return w;}
                                         
ZZn12 operator*(int y,const ZZn12& x)
{ZZn12 w=x; w.a*=y; w.b*=y; return w;}

ZZn12 operator/(const ZZn12& x,const ZZn12& y)
{ZZn12 w=x; w/=y; return w;}

ZZn12 operator/(const ZZn12& x,const ZZn6& y)
{ZZn12 w=x; ZZn6 j=inverse(y); w.a*=j; w.b*=j; return w;} //
#ifndef MR_NO_RAND
ZZn12 randn12(void)
{ZZn12 w; w.a=randn6(); w.b=randn6(); return w;}
#endif
#ifndef MR_NO_STANDARD_IO

ostream& operator<<(ostream& s,ZZn12& b)
{
    int i;
    ZZn6 x,y;
    b.get(x,y);
    s << "[" << x << "," << y << "]";
    return s;    
}

#endif

// Left to right method - with windows

ZZn12 pow(const ZZn12* t,const ZZn12& x,const Big& k)
{
    int i,j,nb,n,nbw,nzs;
    ZZn12 u=x;

    if (k==0) return (ZZn12)1;
    if (k==1) return u;

    nb=bits(k);
    if (nb>1) for (i=nb-2;i>=0;)
    {
        n=window(k,i,&nbw,&nzs,5);
        for (j=0;j<nbw;j++) u*=u;
        if (n>0) u*=t[n/2];
        i-=nbw;
        if (nzs)
        {
            for (j=0;j<nzs;j++) u*=u;
            i-=nzs;
        }
    }
    return u;
}

void precompute(const ZZn12& x,ZZn12* t)
{
    int i;
    ZZn12 u2,u=x;
    u2=(u*u);
    t[0]=u;
   
    for (i=1;i<16;i++)
        t[i]=u2*t[i-1];

}

/*
ZZn12 pow(const ZZn12& x,const Big& k)
{
    ZZn12 u,t[16];

    if (k==0) return (ZZn12)1;
    u=x;
    if (k==1) return u;
//
// Prepare table for windowing
//
    precompute(u,t);
    return pow(t,u,k);
}
*/

// If k is low Hamming weight this will be just as good..

ZZn12 pow(const ZZn12& x,const Big& k)
{
    int i,j,nb,n,nbw,nzs;
    ZZn12 u=x;

    if (k==0) return (ZZn12)1;
    if (k==1) return u;

    nb=bits(k);
    if (nb>1) for (i=nb-2;i>=0;i--)
    {
        u*=u;
        if (bit(k,i)) u*=x;
    }

    return u;
}


// standard MIRACL multi-exponentiation

ZZn12 pow(int n,const ZZn12* x,const Big* b)
{
    int k,j,i,m,nb,ea;
    ZZn12 *G;
    ZZn12 r;
    m=1<<n;
    G=new ZZn12[m];

 // precomputation
    
    for (i=0,k=1;i<n;i++)
    {
        for (j=0; j < (1<<i) ;j++)
        {
            if (j==0)   G[k]=x[i];
            else        G[k]=G[j]*x[i];      
            k++;
        }
    }

    nb=0;
    for (j=0;j<n;j++) 
        if ((k=bits(b[j]))>nb) nb=k;

    r=1;
    for (i=nb-1;i>=0;i--) 
    {
        ea=0;
        k=1;
        for (j=0;j<n;j++)
        {
            if (bit(b[j],i)) ea+=k;
            k<<=1;
        }
        r*=r;
        if (ea!=0) r*=G[ea];
    }
    delete [] G;
    return r;
}
