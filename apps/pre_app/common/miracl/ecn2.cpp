/*
 *    MIRACL  C++ Implementation file ecn2cpp
 *
 *    AUTHOR  : M. Scott
 *  
 *    PURPOSE : Implementation of class ECn2  (Elliptic curves over n^2)
 *
 * WARNING: This class has been cobbled together for a specific use with
 * the MIRACL library. It is not complete, and may not work in other 
 * applications
 *
 *    Copyright (c) 2001 Shamus Software Ltd.
 */


#include "ecn2.h"

using namespace std;

void ECn2::get(ZZn2& a,ZZn2& b,ZZn2& c)
{a=x;b=y;c=z;}

void ECn2::get(ZZn2& a,ZZn2& b)
{norm(); a=x;b=y;}

void ECn2::get(ZZn2& a)
{norm(); a=x;}

void ECn2::getZ(ZZn2& a)
{a=z;}

//
// Fp4 number is a+ib = (a,b), where a=u+i^2.v and b=s+i^2.t
//
// Point (x,0),(0,y) on the curve E(Fp4) maps to point (i^2*x,0),(i^4*y,0) on 
// the twist y^2=x^3+i^4.Ax +i^6.B, where i is 4-th root of qnr
//
// 
// Note that the mapped point is actually on E(Fp2) !
//

BOOL ECn2::set(const ZZn2& xx,const ZZn2& yy)
{ 
  BOOL result=TRUE,twist=get_mip()->TWIST;
  int qnr=get_mip()->qnr;

  if (twist)
  {
   if (getA().iszero() || getB().iszero())
   { // In this case use the quartic or sextic twist instead! 
        if (yy*yy != xx*xx*xx-txd(getA()*xx)-txd((ZZn2)getB())) result=FALSE;
   }
   else
   { // quadratic twist
        if (yy*yy != xx*xx*xx+txx(txx(getA()*xx))+txx(txx(txx((ZZn2)getB())))) result=FALSE;
   }
  }
  else
  {
   if (yy*yy != xx*xx*xx+getA()*xx+getB()) result=FALSE;
  }

  x=xx;
  y=yy;
  z=(ZZn2)1;
  marker=MR_EPOINT_NORMALIZED;
  return result;
}

BOOL ECn2::set(const ZZn2& xx)
{ 
  ZZn2 w;
  BOOL twist=get_mip()->TWIST;
  int qnr=get_mip()->qnr;

  if (twist)
  {
        if (getA().iszero() || getB().iszero())
            w=xx*xx*xx-txd(getA()*xx)-txd((ZZn2)getB());
        else
            w=xx*xx*xx+txx(txx(getA()*xx))+txx(txx(txx((ZZn2)getB())));
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
  z=(ZZn2)1;
  marker=MR_EPOINT_NORMALIZED;
  return TRUE;
}

ECn2 operator-(const ECn2& a) 
{ECn2 w; 
 if (a.marker!=MR_EPOINT_INFINITY) 
   {w.x=a.x; w.y=-a.y; w.z=a.z; w.marker=a.marker;} 
 return w; 
}  

ECn2& ECn2::operator*=(const Big& k)
{
    int i,j,n,nb,nbs,nzs;
    ECn2 p2,pt,t[11],P,Q;
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
//    p2.norm();

    t[0]=pt;
    for (i=1;i<=10;i++)
    {
        t[i]=t[i-1]+p2;
//        t[i].norm();
    }
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

ECn2 operator*(const Big& r,const ECn2& P)
{
    ECn2 T=P;
    T*=r;
    return T;
}

#ifndef MR_NO_STANDARD_IO

ostream& operator<<(ostream& s,ECn2& b)
{
    ZZn2 x,y,z;
    if (b.iszero())
        s << "(Infinity)";
    else
    {
        b.norm();
        b.get(x,y);
 
        s << "(" << x << "," << y << ")";
    }
    return s;
}

#endif

ECn2 operator+(const ECn2& a,const ECn2& b)
{ECn2 c=a; c+=b; return c;}

ECn2 operator-(const ECn2& a,const ECn2& b)
{ECn2 c=a; c-=b; return c;}

ECn2& ECn2::operator-=(const ECn2& z)
{ECn2 t=(-z); *this+=t; return *this; }

ECn2& ECn2::operator+=(const ECn2& z)
{
    ZZn2 lam;
    add(z,lam);
    return *this;
}

void ECn2::norm(void)
{ // normalize a point
    
    if (marker!=MR_EPOINT_GENERAL) return;
    ZZn2 izz,iz=inverse(z);
    izz=iz*iz;
    x*=izz;
    izz*=iz;
    y*=izz;
    z=(ZZn2)1;
    marker=MR_EPOINT_NORMALIZED;
}

BOOL ECn2::add(const ECn2& w,ZZn2& lam)
{
    BOOL Doubling,twist=get_mip()->TWIST;
    int qnr=get_mip()->qnr;

    if (marker==MR_EPOINT_INFINITY)
    {
        *this=w;
        return FALSE;
    }
    if (w.marker==MR_EPOINT_INFINITY)
    {
        return FALSE;
    }

    if (get_mip()->coord==MR_AFFINE)
    {
        if (x!=w.x)
        {
            ZZn2 t=y;  t-=w.y;
            ZZn2 t2=x; t2-=w.x;                 // 2 ZZn sqrs, 5 muls, 1 Inverse
            lam=t; lam/=t2;

            x+=w.x; t=lam; t*=t; t-=x; x=t;     // 5 ZZn muls
            y=w.x; y-=x; y*=lam; y-=w.y;   
        }
        else
        {
            if (y!=w.y || y.iszero())
            {
                clear();
                lam=(ZZn2)1; 
                return TRUE;    // any non-zero value
            }
            ZZn2 t=x;
            ZZn2 t2=x;

     //   lam=(3*(x*x)+getA())/(y+y);

            lam=x;
            lam*=lam;
            lam*=3;
            if (twist) lam+=qnr*getA();
            else       lam+=getA();
            lam/=(y+y);                         // 2 sqrs, 7 muls and 1 inverse

            t2+=x;
            x=lam;
            x*=x;
            x-=t2;
         
            t-=x;
            t*=lam;
            t-=y;
            y=t;                                // 5 ZZn muls
        }
      
        z=(ZZn2)1;
        marker=MR_EPOINT_NORMALIZED;
        return TRUE;
    }

    ZZn2 Xzz=w.x;
    ZZn2 Yzzz=w.y;
    ZZn2 xZZ=x;
    ZZn2 yZZZ=y;
    ZZn2 zz,ZZ;
    
    Doubling=FALSE;
    if (this==&w) Doubling=TRUE;

    if (!Doubling)
    { // maybe we are really doubling? Or P-=P?
        if (w.marker!=MR_EPOINT_NORMALIZED) {ZZ=w.z*w.z; xZZ*=ZZ; yZZZ*=(ZZ*w.z);}
        if (marker!=MR_EPOINT_NORMALIZED)  {zz=z*z; Xzz*=zz; Yzzz*=(zz*z);} 

        if (Xzz==xZZ)
        {
            if (Yzzz!=yZZZ || y.iszero())
            { // P-=P = O
                clear();
                lam=(ZZn2)1; 
                return TRUE; 
               
            }
            else
            {
                Doubling=TRUE;
            }
        }
    }

    if (!Doubling)
    { // addition
        ZZn2 t,x2,u,t2;

        t=xZZ-Xzz;
        lam=yZZZ-Yzzz;

        z*=t;
        if (w.marker!=MR_EPOINT_NORMALIZED) z*=w.z;
        
        t2=(t*t);
        u=(xZZ+Xzz)*t2;
        x2=lam*lam-u;
        u-=(x2+x2);
        y=(u*lam-(yZZZ+Yzzz)*t2*t)/2;
        x=x2; 
    }
    else
    { // doubling
        ZZn2 t,yy=y*y;
        int A=get_mip()->Asize;

        if (A!=0)
        {
            if (twist) A*=qnr;
            zz=z*z;
            if (A==-3)
            {
                lam=(x-zz)*(x+zz);
                lam+=(lam+lam);
            }
            else
            {
                ZZn AA=getA();
                if (twist) AA*=qnr;
                lam=x*x; lam+=(lam+lam);
                lam+=AA*(zz*zz);
            }
        }
        else
        { lam=x*x; lam+=(lam+lam); }

        t=x*yy; t+=t; t+=t;
        x=lam*lam-(t+t);
        z*=y; z+=z;
        yy+=yy; yy*=yy; yy+=yy;  // 8*y^2
        y=lam*(t-x)-yy; 
    }
    marker=MR_EPOINT_GENERAL;

    return TRUE;
}

