/*
 *    MIRACL  C++ Implementation file ZZn6a.cpp
 *
 *    AUTHOR  : M. Scott
 *  
 *    PURPOSE : Implementation of class ZZn6  (Arithmetic over n^6)
 *
 * WARNING: This class has been cobbled together for a specific use with
 * the MIRACL library. It is not complete, and may not work in other 
 * applications
 *
 *    Copyright (c) 2006 Shamus Software Ltd.
 */

#include "zzn6a.h"

using namespace std;

// Frobenius X=x^p

ZZn6& ZZn6::powq(const ZZn6& X)
{ 
    *this=(ZZn6)conj(a)+X*conj(b)+(X*X)*conj(c);
    return *this;
}

void ZZn6::get(ZZn2& x,ZZn2& y,ZZn2& z)  
{x=a; y=b; z=c;} 

void ZZn6::get(ZZn2& x) 
{x=a; }

ZZn6& ZZn6::operator*=(const ZZn6& x)
{ // optimized to reduce constructor/destructor calls
 if (&x==this)
 { // Chung-Hasan SQR2
    ZZn2 A,B,C,D;
    A=a; A*=A;
    B=b*c; B+=B;
    C=c; C*=C;
    D=a*b; D+=D;
    c+=(a+b); c*=c;

    a=A-txx(B);
    b=D-txx(C);
    c-=(A+B+C+D);
 }
 else
 { // Karatsuba
    ZZn2 Z0,Z1,Z2,Z3,Z4,T0,T1;
    Z0=a*x.a;
    Z2=b*x.b;
    Z4=c*x.c;
    T0=a+b;
    T1=x.a+x.b;
    Z1=T0*T1;
    Z1-=Z0;
    Z1-=Z2;
    T0=b+c;
    T1=x.b+x.c;
    Z3=T0*T1;
    Z3-=Z2;
    Z3-=Z4;
    T0=a+c;
    T1=x.a+x.c;
    T0*=T1;
    Z2+=T0;
    Z2-=Z0;
    Z2-=Z4;

    a=Z0-txx(Z3);
    b=Z1-txx(Z4);
    c=Z2;
 }
 return *this;
}

ZZn6& ZZn6::operator/=(const ZZn2& x)
{
    *this*=inverse(x);
    return *this;
}

ZZn6& ZZn6::operator/=(const ZZn& x)
{
    ZZn t=(ZZn)1/x;
    a*=t;
    b*=t;
    c*=t;
    return *this;
}

ZZn6& ZZn6::operator/=(int i)
{
    ZZn t=(ZZn)1/i;
    a*=t;
    b*=t;
    c*=t;
    return *this;
}

ZZn6& ZZn6::operator/=(const ZZn6& x)
{
    *this*=inverse(x);
    return *this;
}

ZZn6 inverse(const ZZn6& w)
{
    ZZn6 y;
    ZZn2 f0;

    y.a=w.a*w.a+txx(w.b*w.c);
    y.b=-txx(w.c*w.c)-w.a*w.b;
    y.c=w.b*w.b-w.a*w.c;

    f0=-txx(w.b*y.c)+w.a*y.a-txx(w.c*y.b);
    f0=inverse(f0);

    y.c*=f0;
    y.b*=f0;
    y.a*=f0;

    return y;
}

ZZn6 operator+(const ZZn6& x,const ZZn6& y) 
{ZZn6 w=x; w.a+=y.a; w.b+=y.b; w.c+=y.c; return w; } 

ZZn6 operator+(const ZZn6& x,const ZZn2& y) 
{ZZn6 w=x; w.a+=y; return w; } 

ZZn6 operator+(const ZZn6& x,const ZZn& y) 
{ZZn6 w=x; w.a+=y; return w; } 

ZZn6 operator-(const ZZn6& x,const ZZn6& y) 
{ZZn6 w=x; w.a-=y.a; w.b-=y.b; w.c-=y.c; return w; } 

ZZn6 operator-(const ZZn6& x,const ZZn2& y) 
{ZZn6 w=x; w.a-=y; return w; } 

ZZn6 operator-(const ZZn6& x,const ZZn& y) 
{ZZn6 w=x; w.a-=y; return w; } 

ZZn6 operator-(const ZZn6& x) 
{ZZn6 w; w.a=-x.a; w.b=-x.b; w.c-=x.c; return w; } 

ZZn6 operator*(const ZZn6& x,const ZZn6& y)
{
 ZZn6 w=x;  
 if (&x==&y) w*=w;
 else        w*=y;  
 return w;
}

ZZn6 operator*(const ZZn6& x,const ZZn2& y)
{ZZn6 w=x; w*=y; return w;}

ZZn6 operator*(const ZZn6& x,const ZZn& y)
{ZZn6 w=x; w*=y; return w;}

ZZn6 operator*(const ZZn2& y,const ZZn6& x)
{ZZn6 w=x; w*=y; return w;}

ZZn6 operator*(const ZZn& y,const ZZn6& x)
{ZZn6 w=x; w*=y; return w;}

ZZn6 operator*(const ZZn6& x,int y)
{ZZn6 w=x; w*=y; return w;}

ZZn6 operator*(int y,const ZZn6& x)
{ZZn6 w=x; w*=y; return w;}

ZZn6 operator/(const ZZn6& x,const ZZn6& y)
{ZZn6 w=x; w/=y; return w;}

ZZn6 operator/(const ZZn6& x,const ZZn2& y)
{ZZn6 w=x; w/=y; return w;}

ZZn6 operator/(const ZZn6& x,const ZZn& y)
{ZZn6 w=x; w/=y; return w;}

ZZn6 operator/(const ZZn6& x,int i)
{ZZn6 w=x; w/=i; return w;}
#ifndef MR_NO_RAND
ZZn6 randn6(void)
{ZZn6 w; w.a=randn2(); w.b=randn2(); w.c=randn2(); return w;}
#endif
ZZn6 tx(const ZZn6& w)
{
    ZZn6 u=w;
    
    ZZn2 t=u.a;
    u.a=-txx(u.c);
    u.c=u.b;
    u.b=t;

    return u;
}


// regular ZZn6 powering

ZZn6 pow(const ZZn6& x,const Big& k)
{
    int i,j,nb,n,nbw,nzs;
    ZZn6 u,u2,t[16];
    if (k==0) return (ZZn6)1;
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

ZZn6 powl(const ZZn6& x,const Big& k)
{
     ZZn6 w8,w9,two,y;
     int i,nb;

     two=(ZZn)2;
     y=two*x;
     if (k==0) return (ZZn6)two;
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

ostream& operator<<(ostream& s,const ZZn6& xx)
{
    ZZn6 b=xx;
    ZZn2 x,y,z;
    b.get(x,y,z);
    s << "[" << x << "," << y << "," << z << "]";
    return s;    
}

#endif

