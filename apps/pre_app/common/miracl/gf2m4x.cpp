/*
 *    MIRACL C++ Implementation file gf2m4x.cpp
 *
 *    AUTHOR   : M. Scott
 *
 *    PURPOSE  : Implementation of class GF2m4x (Quartic extension over 2^m)
 *
 * WARNING: This class has been cobbled together for a specific use with
 * the MIRACL library. It is not complete, and may not work in other 
 * applications
 *
 */

#include "gf2m4x.h"

using namespace std;

void GF2m4x::get(GF2m& a,GF2m& b,GF2m& c,GF2m &d)
{a=x[0]; b=x[1]; c=x[2]; d=x[3];}

void GF2m4x::get(GF2m& a,GF2m& b)
{a=x[0]; b=x[1];}

void GF2m4x::get(GF2m& a)
{a=x[0];}

int GF2m4x::degree()
{
    if (!x[3].iszero()) return 3;
    if (!x[2].iszero()) return 2;
    if (!x[1].iszero()) return 1;
    return 0;
}

GF2m4x& GF2m4x::powq()
{
    GF2m t=x[1];     // t=c
    int r=(get_mip()->M)%4;

    if (r==0) return *this;
    if (r==1)
    {
        x[0]+=x[2];      // d=b+d 
        x[1]=x[2];       // c=b
        x[2]=x[3];
        x[2]+=t;         // b=a+c
       
    }
    if (r==2)
    {
        x[0]+=(x[1]+x[2]+x[3]);
        x[1]+=x[3];
        x[2]+=x[3];
    }
    if (r==3)
    {
        x[0]+=t;          // d=c+d
        x[1]=x[2];
        x[1]+=x[3];       // c=a+b
        x[2]=t;           // b=c
    }

    return *this;
}

GF2m4x& GF2m4x::operator*=(const GF2m4x& b)
{
    GF2m x4;
    if (this==&b)
    { // squaring
        x[3]*=x[3];
        x4=x[2]; x4*=x4;
        x[2]=x[1]; x[2]*=x[2];
        x[0]*=x[0];

        x[2]+=x[3];
        x[0]+=x4;
        x[1]=x4;

       return *this;
    }
    else
    { // Use Karatsuba
/*
        int i;
        big A[4],B[4],C[8],T[8];
        GF2m x4,x5,x6;
        GF2m4x bb=b;

        char *memc=(char *)memalloc(16);

        for (i=0;i<8;i++)
        {
            C[i]=mirvar_mem(memc,i);
            T[i]=mirvar_mem(memc,i+8);
        }

        for (i=0;i<4;i++)
        {
            A[i]=getbig(x[i]);
            B[i]=getbig(bb.x[i]);
        }

        karmul2_poly(4,T,A,B,C);

        for (i=0;i<4;i++) x[i]=C[i];

        x4=C[4];
        x5=C[5];
        x6=C[6];

        memkill(memc,16);
*/

// fastest

        GF2m x5,x6,w1,w0,z1,z0,z1w1,z0w0,t; 

        w1=x[1]; w1+=x[3]; w0=x[0]; w0+=x[2];
        z1=b.x[1]; z1+=b.x[3]; z0=b.x[0]; z0+=b.x[2];
        z1w1=z1; z1w1*=w1; z0w0=z0; z0w0*=w0;

        x6=x[1]; x6*=b.x[1];
        x5=x[2]; x5*=b.x[2];
        x4=x6; x4+=x5; 

        x[1]+=x[0]; t=b.x[0]; t+=b.x[1];  x[1]*=t;   
        x[0]*=b.x[0]; x[1]+=x[0]; x[1]+=x6;

        t=x[2]; t+=x[3]; x6=b.x[2]; x6+=b.x[3]; t*=x6;
        x5+=t;
        x6=x[3]; x6*=b.x[3];
        x5+=x6;

        t=z0; t+=z1; x[3]=t; t=w0; t+=w1; x[3]*=t;

        x[3]+=z1w1; x[3]+=z0w0; x[3]+=x5; x[3]+=x[1];

        x[2]=x4; x[2]+=x[0]; x[2]+=z0w0;
        x4+=x6; x4+=z1w1;

/*
        GF2m x4,x5,x6;
        x6=x[3]*b.x[3];
        x5=x[3]*b.x[2]+x[2]*b.x[3];
        x4=x[3]*b.x[1]+x[2]*b.x[2]+x[1]*b.x[3];
        x[3]=x[3]*b.x[0]+x[2]*b.x[1]+x[1]*b.x[2]+x[0]*b.x[3];
        x[2]=x[2]*b.x[0]+x[1]*b.x[1]+x[0]*b.x[2];
        x[1]=x[1]*b.x[0]+x[0]*b.x[1];
        x[0]=x[0]*b.x[0];
*/

// reduction    mod x^4+x+1

        x[2]+=x6;
        x[3]+=x6;
        x[1]+=x5;
        x[2]+=x5;
        x[0]+=x4;
        x[1]+=x4;

        return *this;
    }
}

GF2m4x& GF2m4x::operator*=(const GF2m& b)
{ // specialised for our circumstances
   x[0]*=b;
   if (x[1].isone())   x[1]=b;
   else                x[1]*=b;
   if (x[2].isone())   x[2]=b;
   else                x[2]*=b;
   if (!x[3].iszero()) x[3]*=b;
   return *this;
}


GF2m4x& GF2m4x::operator/=(const GF2m& b)
{
   GF2m ib=(GF2m)1/b;
   x[0]*=ib;
   x[1]*=ib;
   x[2]*=ib;
   x[3]*=ib;
   return *this;
}

//
// Lim & Hwang - just one field inversion
//

void GF2m4x::invert()
{
    int degF,degG,degB,degC,d,i,j;
    GF2m alpha,beta,gamma,BB[5],FF[5],CC[5],GG[5];

    GF2m *B=BB,*C=CC,*F=FF,*G=GG,*T; 

    C[0]=1;
    F[4]=F[1]=F[0]=1;  // f(x)

    degF=4; degG=degree(); degC=0; degB=-1;

    if (degG==0)
    {
        x[0]=(GF2m)1/x[0];
        return;
    }

    for (i=0;i<4;i++)
    {
        G[i]=x[i];
        x[i]=0;
    }
    while (degF!=0)
    {
        if (degF<degG)
        { // swap
            T=F; F=G; G=T;  d=degF; degF=degG; degG=d;
            T=B; B=C; C=T;  d=degB; degB=degC; degC=d;
        }
        j=degF-degG;
        alpha=G[degG]*G[degG]; 
        beta=F[degF]*G[degG];
        gamma=G[degG]*F[degF-1] + F[degF]*G[degG-1];

        for (i=0;i<=degF;i++ )
        {
            F[i]*=alpha;
            if (i>=j-1) F[i]+=gamma*G[i-j+1];
            if (i>=j)   F[i]+=beta*G[i-j];           
        }
        for (i=0;i<=degB || i<=degC+j;i++)
        {
            B[i]*=alpha;
            if (i>=j-1) B[i]+=gamma*C[i-j+1];
            if (i>=j)   B[i]+=beta*C[i-j];
        }
        while (degF>=0 && F[degF]==0) degF--;

        if (degF==degG)
        {
            alpha=F[degF];
            for (i=0;i<=degF;i++)
            {
                F[i]*=G[degF];
                F[i]+=alpha*G[i];
            }
           
            for (i=0;i<=4-degF;i++)
            {
                B[i]*=G[degF];
                B[i]+=alpha*C[i];
            }
            while (degF>=0 && F[degF]==0) degF--;
        }
        degB=3; while (degB>=0 && B[degB]==0) degB--;
    }

    alpha=(GF2m)1/F[0];
    for (i=0;i<=degB;i++)
        x[i]=alpha*B[i]; 
    return;
}

GF2m4x& GF2m4x::operator/=(const GF2m4x& a)
{
    GF2m4x b=a;
    b.invert();
    *this *= b;
    return *this;
}

GF2m4x operator+(const GF2m4x& a,const GF2m4x& b)
{ GF2m4x r=a; r+=b; return r;}

GF2m4x operator+(const GF2m4x& a,const GF2m& b)
{ GF2m4x r=a; r+=b; return r;}
 
GF2m4x operator+(const GF2m& a,const GF2m4x& b)
{ GF2m4x r=b; r+=a; return r;}

GF2m4x operator/(const GF2m4x& a,const GF2m& b)
{ GF2m4x r=a; r/=b; return r; }


// special purpose mul, a and b are of the form (x,y,y+1,0)
// only 3 muls...

GF2m4x mul(const GF2m4x& a,const GF2m4x& b)
{
    GF2m p,w,t,q,tw,pq,z;
    GF2m4x r;

    p=a.x[0]; w=a.x[1];
    q=b.x[0]; t=b.x[1];

    z=(w+p)*(t+q);

    tw=t*w; pq=p*q; // 2x2 Karatsuba

    z+=tw; z+=pq;   // z=wq+tp

    w+=t;
    t=w+tw+1;

    r.set(pq+t,z+t,z+p+q+tw,w);
    return r;

}

GF2m4x operator*(const GF2m4x& a,const GF2m4x& b)
{ 
    GF2m4x r=a;
    if (&a!=&b) r*=b; 
    else r*=r;
    return r;
}

GF2m4x operator/(const GF2m4x& a,const GF2m4x& b)
{ 
    GF2m4x r=a;
    r/=b; 
    return r;
}

GF2m4x operator*(const GF2m4x& a,const GF2m& b)
{ GF2m4x r=a; r*=b; return r;}
GF2m4x operator*(const GF2m& a,const GF2m4x& b)
{ GF2m4x r=b; r*=a; return r;}

#ifndef MR_NO_RAND
GF2m4x randx4(void)
{
    int m=get_mip()->M;
    GF2m4x r;
    r.x[0]=rand(m,2);        
    r.x[1]=rand(m,2);        
    r.x[2]=rand(m,2);        
    r.x[3]=rand(m,2);        
    return r;
}
#endif

GF2m4x pow(const GF2m4x& a,const Big& k)
{
    int i,j,nb,n,nbw,nzs;
    GF2m4x u,u2,t[16];
    if (k.iszero()) return (GF2m4x)1;
    u=a;
    if (k.isone()) return u;

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

ostream& operator<<(ostream& os,const GF2m4x& x)
{
    GF2m4x u=x;
    GF2m a,b,c,d;
 
    u.get(a,b,c,d);

    os << "[" << (Big)a << "," << (Big)b << "," << (Big)c << "," << (Big)d << "]";
    return os;
}

