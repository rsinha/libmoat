/*
 *    MIRACL  C++ Implementation file ecn4.cpp
 *
 *    AUTHOR  : M. Scott
 *  
 *    PURPOSE : Implementation of class ECn4  (Elliptic curves over n^4)
 *
 * WARNING: This class has been cobbled together for a specific use with
 * the MIRACL library. It is not complete, and may not work in other 
 * applications
 *
 *    Copyright (c) 2001 Shamus Software Ltd.
 */


#include "ecn4.h"

using namespace std;

void ECn4::get(ZZn4& a,ZZn4& b)
{a=x;b=y;}

void ECn4::get(ZZn4& a)
{a=x;}

//
// Point (x,0),(0,y) on the curve E(Fp8) maps to point (i^2*x,0),(i^4*y,0) on 
// the twist y^2=x^3+i^4.Ax +i^6.B, where i is 8-th root of qnr
//
// 
// Note that the mapped point is actually on E(Fp4) !
//

BOOL ECn4::set(const ZZn4& xx,const ZZn4& yy)
{ 
  BOOL twist=get_mip()->TWIST;

  if (twist)
  {
      ZZn4 a4,b6;
      ZZn2 x((ZZn)0,getA());
      ZZn2 y((ZZn)0,getB());
      a4.set(x,(ZZn2)0);     // A*i^4
      b6.set((ZZn2)0,y);     // B*i^6

      if (yy*yy != xx*xx*xx+a4*xx+b6) return FALSE;
  }
  else
  {
      if (yy*yy != xx*xx*xx+getA()*xx+getB()) return FALSE;
  }
  x=xx;
  y=yy;
  marker=MR_EPOINT_GENERAL;
  return TRUE;
}

BOOL ECn4::set(const ZZn4& xx)
{ 
 ZZn4 s,w;
 BOOL twist=get_mip()->TWIST;

 if (twist)
 {
      ZZn4 a4,b6;
      ZZn2 x((ZZn)0,getA());
      ZZn2 y((ZZn)0,getB());
      a4.set(x,(ZZn2)0);     // A*i^4
      b6.set((ZZn2)0,y);     // B*i^6
      w=xx*xx*xx+a4*xx+b6;
 }
 else
 {
     w=xx*xx*xx+getA()*xx+getB();
 }
 if (!w.iszero())
 {
  w=sqrt(w); 
  if (w.iszero()) return FALSE;
 }
 x=xx;
 y=w;
 marker=MR_EPOINT_GENERAL;
 return TRUE;
}

ECn4 operator-(const ECn4& a) 
{ECn4 w; 
 if (a.marker!=MR_EPOINT_INFINITY) 
   {w.x=a.x; w.y=-a.y; w.marker=a.marker;} 
 return w; 
}  

ECn4& ECn4::operator*=(const Big& k)
{
    int i,j,n,nb,nbs,nzs;
    ECn4 p2,pt,t[11];
    Big h,kk;

    if (k==0)
    {
        clear();
        return *this;
    }
    if (k==1)
    {
        return (*this);
    }

    pt=*this;
    kk=k;
    if (kk<0)
    {
        pt=-pt;
        kk=-k;
    }
    h=3*kk;

    p2=pt+pt; 
    t[0]=pt;
    for (i=1;i<=10;i++)
        t[i]=t[i-1]+p2;

// Left to Right method

    nb=bits(h);
    for (i=nb-2;i>=1;)
    {
        n=naf_window(kk,h,i,&nbs,&nzs,5);
        for (j=0;j<nbs;j++) pt+=pt;
        if (n>0) pt+=t[n/2];
        if (n<0) pt-=t[(-n)/2];
        i-=nbs;
        if (nzs)
        {
            for (j=0;j<nzs;j++) pt+=pt;
            i-=nzs;
        }
    }
    *this=pt;
    return *this;
}

ECn4 operator*(const Big& r,const ECn4& P)
{
    ECn4 T=P;
    T*=r;
    return T;
}

#ifndef MR_NO_STANDARD_IO

ostream& operator<<(ostream& s,ECn4& b)
{
    ZZn4 x,y;
    if (b.iszero())
        s << "(Infinity)";
    else
    {
        b.get(x,y);
        s << "(" << x << "," << y << ")";
    }
    return s;
}

#endif

ECn4 operator+(const ECn4& a,const ECn4& b)
{ECn4 c=a; c+=b; return c;}

ECn4 operator-(const ECn4& a,const ECn4& b)
{ECn4 c=a; c-=b; return c;}

ECn4& ECn4::operator-=(const ECn4& z)
{ECn4 t=(-z); *this+=t; return *this; }

ECn4& ECn4::operator+=(const ECn4& z)
{
    ZZn4 lam;
    add(z,lam);
    return *this;
}

BOOL ECn4::add(const ECn4& z,ZZn4& lam)
{
    BOOL twist=get_mip()->TWIST;

    if (marker==MR_EPOINT_INFINITY)
    {
        *this=z;
        return FALSE;
    }
    if (z.marker==MR_EPOINT_INFINITY)
    {
        return FALSE;
    }

    if (x!=z.x)
    {
        ZZn4 t=y;  t-=z.y;
        ZZn4 t2=x; t2-=z.x;     
        lam=t; lam/=t2;

        x+=z.x; t=lam; t*=t; t-=x; x=t;  
        y=z.x; y-=x; y*=lam; y-=z.y;   

    }
    else
    {
        if (y!=z.y || y.iszero())
        {
            clear();
            lam=(ZZn4)1; 
            return TRUE;    // any non-zero value
        }
        ZZn4 t=x;
        ZZn4 t2=x;

     //   lam=(3*(x*x)+getA())/(y+y);

        lam=x;
        lam*=lam;
        lam*=3;
        if (twist)
        {
            ZZn4 a4;
            ZZn2 x((ZZn)0,getA());
            a4.set(x,(ZZn2)0);     // A*i^4
            lam+=a4;
        }
        else  lam+=getA();
        lam/=(y+y);       

        t2+=x;
        x=lam;
        x*=x;
        x-=t2;
         
        t-=x;
        t*=lam;
        t-=y;
        y=t;           
    }

    marker=MR_EPOINT_GENERAL;    
    return TRUE;
}

