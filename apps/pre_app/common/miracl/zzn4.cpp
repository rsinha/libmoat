/*
 *    MIRACL  C++ Implementation file zzn4.cpp
 *
 *    AUTHOR  : M. Scott
 *  
 *    PURPOSE : Implementation of class ZZn4  (Arithmetic over n^4)
 *
 * WARNING: This class has been cobbled together for a specific use with
 * the MIRACL library. It is not complete, and may not work in other 
 * applications
 *
 *    Note: This code assumes that -2 is a Quadratic Non-Residue,
 *          so modulus p=5 mod 8
 *          OR p=3 mod 8
 *          OR p=7 mod 8, p=1 mod 3
 *
 *   For example for p=3 mod 8 the representation is
 *
 *   A+IB, where A=(a+ib), B=(c+id), I=sqrt(1+i)
 *   where i=sqrt(-1)
 *
 *    Copyright (c) 2006 Shamus Software Ltd.
 */

#include "zzn4.h"

using namespace std;

ZZn4& ZZn4::powq(const ZZn2 &m)
{ 
    a.conj(); b.conj();
    b*=m;
    return *this;
}

void ZZn4::get(ZZn2& x,ZZn2& y)  
{x=a; y=b;} 

void ZZn4::get(ZZn2& x) 
{x=a; }

ZZn4& ZZn4::operator*=(const ZZn4& x)
{ // optimized to reduce constructor/destructor calls
 if (&x==this)
 { /* Karatsuba */
    ZZn2 t=a;
    t+=b;
    a*=a; 
    b*=b;
    t*=t;
    t-=a;
    t-=b; 
    a+=txx(b);
    b=t;

/* Colm O'hEigeartaigh spotted this possible improvement - thanks Colm

    ZZn2 t=a; t+=b;
    ZZn2 t2=a; t2+=txx(b);
    t*=t2;
    b*=a;
    t-=b;
    t-=txx(b);
    b+=b;
    a=t;
*/
 }
 else
 {
    ZZn2 ac=a; ac*=x.a;
    ZZn2 bd=b; bd*=x.b;
    ZZn2 t=x.a; t+=x.b;
    b+=a; b*=t; b-=ac; b-=bd;
    a=ac; a+=txx(bd);
 }
 return *this;
}

ZZn4& ZZn4::operator/=(const ZZn2& x)
{
    *this*=inverse(x);
    return *this;
}

ZZn4& ZZn4::operator/=(const ZZn& x)
{
    ZZn t=(ZZn)1/x;
    a*=t;
    b*=t;
    return *this;
}

ZZn4& ZZn4::operator/=(int i)
{
    ZZn t=(ZZn)1/i;
    a*=t;
    b*=t;
    return *this;
}

ZZn4& ZZn4::operator/=(const ZZn4& x)
{
 *this*=inverse(x);
 return *this;
}

ZZn4 inverse(const ZZn4& w)
{
    ZZn4 y=conj(w);
    ZZn2 u=w.a;
    ZZn2 v=w.b;
    u*=u;
    v*=v;
    u-=txx(v);
    u=inverse(u);
    y*=u;
    return y;
}

ZZn4 operator+(const ZZn4& x,const ZZn4& y) 
{ZZn4 w=x; w.a+=y.a; w.b+=y.b; return w; } 

ZZn4 operator+(const ZZn4& x,const ZZn2& y) 
{ZZn4 w=x; w.a+=y; return w; } 

ZZn4 operator+(const ZZn4& x,const ZZn& y) 
{ZZn4 w=x; w.a+=y; return w; } 

ZZn4 operator-(const ZZn4& x,const ZZn4& y) 
{ZZn4 w=x; w.a-=y.a; w.b-=y.b; return w; } 

ZZn4 operator-(const ZZn4& x,const ZZn2& y) 
{ZZn4 w=x; w.a-=y; return w; } 

ZZn4 operator-(const ZZn4& x,const ZZn& y) 
{ZZn4 w=x; w.a-=y; return w; } 

ZZn4 operator-(const ZZn4& x) 
{ZZn4 w; w.a=-x.a; w.b=-x.b; return w; } 

ZZn4 operator*(const ZZn4& x,const ZZn4& y)
{
 ZZn4 w=x;  
 if (&x==&y) w*=w;
 else        w*=y;  
 return w;
}

ZZn4 operator*(const ZZn4& x,const ZZn2& y)
{ZZn4 w=x; w*=y; return w;}

ZZn4 operator*(const ZZn4& x,const ZZn& y)
{ZZn4 w=x; w*=y; return w;}

ZZn4 operator*(const ZZn2& y,const ZZn4& x)
{ZZn4 w=x; w*=y; return w;}

ZZn4 operator*(const ZZn& y,const ZZn4& x)
{ZZn4 w=x; w*=y; return w;}

ZZn4 operator*(const ZZn4& x,int y)
{ZZn4 w=x; w*=y; return w;}

ZZn4 operator*(int y,const ZZn4& x)
{ZZn4 w=x; w*=y; return w;}

ZZn4 operator/(const ZZn4& x,const ZZn4& y)
{ZZn4 w=x; w/=y; return w;}

ZZn4 operator/(const ZZn4& x,const ZZn2& y)
{ZZn4 w=x; w/=y; return w;}

ZZn4 operator/(const ZZn4& x,const ZZn& y)
{ZZn4 w=x; w/=y; return w;}

ZZn4 operator/(const ZZn4& x,int i)
{ZZn4 w=x; w/=i; return w;}
#ifndef MR_NO_RAND
ZZn4 randn4(void)
{ZZn4 w; w.a=randn2(); w.b=randn2(); return w;}
#endif
BOOL is_on_curve(const ZZn4& x)
{
    ZZn4 s,w;
    BOOL twist=get_mip()->TWIST;

    if (twist)
    {
        ZZn4 a4,b6;
        ZZn2 xx((ZZn)0,getA());
        ZZn2 y((ZZn)0,getB());
        a4.set(xx,(ZZn2)0);     // A*i^4
        b6.set((ZZn2)0,y);     // B*i^6
        w=x*x*x+a4*x+b6;
    }
    else
    {
        w=x*x*x+getA()*x+getB();
    }
    if (qr(w)) return TRUE;
    return FALSE;
}

BOOL qr(const ZZn4& x)
{
    ZZn2 a,s;
    if (x.iszero()) return TRUE;
    if (x.b.iszero()) return TRUE;
    s=x.b; s*=s; 
    a=x.a; a*=a; a-=txx(s);
    if (!qr(a)) return FALSE;
    return TRUE;
/*
    s=sqrt(a);
    if (qr((x.a+s)/2) || qr((x.a-s)/2)) return TRUE;
    exit(0);
    return FALSE;
*/
}

ZZn4 sqrt(const ZZn4& x)
{
// sqrt(a+xb) = sqrt((a+sqrt(a*a-n*b*b))/2)+x.b/(2*sqrt((a+sqrt(a*a-n*b*b))/2))
// sqrt(a) = x.sqrt(a/n)
// where x*x=n

    ZZn4 w;
    ZZn2 a,s,t;
    if (x.iszero()) return w;

    if (x.b.iszero())
    {
        if (qr(x.a))
        {
            s=sqrt(x.a);
            w.a=s; w.b=0;
        }
        else
        {
            s=sqrt(txd(x.a));
            w.a=0; w.b=s;
        }
        return w;
    }

    s=x.b; s*=s; 
    a=x.a; a*=a; a-=txx(s);
    s=sqrt(a);

    if (s.iszero()) return w;


    if (qr((x.a+s)/2))
    {
        a=sqrt((x.a+s)/2);
    }
    else
    {
        a=sqrt((x.a-s)/2);
        if (a.iszero()) return w;
    }

    w.a=a;
    w.b=x.b/(2*a);

    return w;
}

ZZn4 conj(const ZZn4& x)
{
    ZZn4 u=x;
    u.conj();
    return u;
}

// For use by ZZn8

ZZn4 tx(const ZZn4& x)
{
    ZZn2 t=txx(x.b);
    ZZn4 u(t,x.a);
    return u;
}

ZZn4 txd(const ZZn4& x)
{
    ZZn2 t=txd(x.a);
    ZZn4 u(x.b,t);
    return u;
}

// regular ZZn4 powering - but see powl function in zzn2.h

ZZn4 pow(const ZZn4& x,const Big& k)
{
    int i,j,nb,n,nbw,nzs;
    ZZn4 u,u2,t[16];
    if (k==0) return (ZZn4)1;
    u=x;
    if (k==1) return u;
//
// Prepare table for windowing
//
    u2=(u*u);
    t[0]=u;
   
    for (i=1;i<16;i++)
        t[i]=u2*t[i-1];

// Left to right method - with windows

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

// standard MIRACL multi-exponentiation

ZZn4 pow(int n,const ZZn4* x,const Big* b)
{
    int k,j,i,m,nb,ea;
    ZZn4 *G;
    ZZn4 r;
    m=1<<n;
    G=new ZZn4[m];
    
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

ZZn4 powl(const ZZn4& x,const Big& k)
{
    ZZn4 w8,w9,two,y;
    int i,nb;

    two=(ZZn)2;
    y=two*x;
    if (k==0)  return (ZZn4)two;
    if (k==1) return y;

    w8=two;
    w9=y;
    nb=bits(k);
    for (i=nb-1;i>=0;i--)
    {
        if (bit(k,i))
        {
            w8*=w9; w8-=y; w9*=w9; w9-=two;
        }
        else
        {
            w9*=w8; w9-=y; w8*=w8; w8-=two;
        }
    }
    return (w8/2);
}

#ifndef MR_NO_STANDARD_IO

ostream& operator<<(ostream& s,const ZZn4& xx)
{
    ZZn4 b=xx;
    ZZn2 x,y;
    b.get(x,y);
    s << "[" << x << "," << y << "]";
    return s;    
}

#endif

