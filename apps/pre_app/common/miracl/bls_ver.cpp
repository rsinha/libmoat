/*

   Boneh-Lynn-Shacham short signature scheme - verification phase
   cl /O2 /GX bls_ver.cpp ecn3.cpp ecn.cpp zzn6.cpp zzn3.cpp zzn.cpp big.cpp ms32.lib

*/

#include <iostream>
#include <fstream>
#include <string.h>
#include "ecn.h"
#include <ctime>
#include "ecn3.h"
#include "zzn6.h"

// cofactor - number of points on curve=CF.q

#define CF 4  

using namespace std;

Miracl precision(40,16); 

// Using SHA-1 as basic hash algorithm

#define HASH_LEN 20

//
// Tate Pairing Code
//
// Extract ECn point in internal ZZn format
//

void extract(ECn& A,ZZn& x,ZZn& y,ZZn& z)
{ 
    big t;
    x=(A.get_point())->X;
    y=(A.get_point())->Y;
    t=(A.get_point())->Z;
    if (A.get_status()!=MR_EPOINT_GENERAL) z=1;
    else                                   z=t;
}

//
// Line from A to destination C. Let A=(x,y)
// Line Y-slope.X-c=0, through A, so intercept c=y-slope.x
// Line Y-slope.X-y+slope.x = (Y-y)-slope.(X-x) = 0
// Now evaluate at Q -> return (Qy-y)-slope.(Qx-x)
//

ZZn6 line(ECn& A,ECn& C,ZZn& slope,ZZn3& Qx,ZZn3& Qy)
{
     ZZn6 w;
     ZZn3 nn=Qx;
     ZZn x,y,z,t;

     extract(A,x,y,z);
     x*=z; t=z; z*=z; z*=t;
     x*=slope; t=slope*z;
     nn*=t; nn-=x; t=z;
     extract(C,x,x,z);
     nn+=(z*y); t*=z;
     w.set(nn,-Qy*t);

     return w;
}

ZZn6 g(ECn& A,ECn& B,ECn& C,ECn& D,ZZn3& Qx,ZZn3& Qy,ZZn3& Sx,ZZn3& Sy)
{
    ZZn6 u;

    ZZn lam;
    big ptr;
    ECn P;
 
    P=A;
    ptr=A.add(B);
    if (ptr==NULL)  return (ZZn6)1;
    lam=ptr; 
    u=line(P,A,lam,Qx,Qy);

    P=C;
    ptr=C.add(D);
    if (ptr==NULL)  return (ZZn6)1;
    lam=ptr;
    return u*line(P,C,lam,Sx,Sy);
}

//
// Fast double-Tate-Pairing, with shared Miller variable and one final exponentiation
//

BOOL fast_double_tate_pairing(ECn& P,ZZn3& Qx,ZZn3& Qy,ECn& R,ZZn3& Sx,ZZn3& Sy,Big& q,Big &cf)
{ 
    int i,j,n,nb,nbw,nzs;
    ECn A1,A2,P2,R2,t1[16],t2[16];
    ZZn6 w,hc,zn[16],res;
    Big m;

    res=zn[0]=1;  

    t1[0]=P2=A1=P;
    t2[0]=R2=A2=R;

    w=g(P2,P2,R2,R2,Qx,Qy,Sx,Sy);

//
// Build windowing table
//
    for (i=1;i<16;i++)
    {
        hc=g(A1,P2,A2,R2,Qx,Qy,Sx,Sy);
        t1[i]=A1;
        t2[i]=A2;
        zn[i]=w*zn[i-1]*hc;
    }

    A1=P;
    A2=R;

/* Left to right method  */
    m=q-1; // skip last iteration
    nb=bits(m);
    for (i=nb-2;i>=0;i-=(nbw+nzs))
    {
        n=window(m,i,&nbw,&nzs,5);  // standard MIRACL windowing

        for (j=0;j<nbw;j++)
        {
            res*=res;    
            res*=g(A1,A1,A2,A2,Qx,Qy,Sx,Sy);
        }
        if (n>0)
        {
            res*=zn[n/2];
            res*=g(A1,t1[n/2],A2,t2[n/2],Qx,Qy,Sx,Sy);
        }  
        for (j=0;j<nzs;j++) 
        {
            res*=res;    
            res*=g(A1,A1,A2,A2,Qx,Qy,Sx,Sy);
        }  
    }

    if (A1!=-P || A2!=-R || res.iszero()) return FALSE;
    w=res;                          
    w.powq();
    res*=w;                        // ^(p+1)

    w=res;
    w.powq(); w.powq(); w.powq();
    res=w/res;                     // ^(p^3-1)

    w=res.powq();
    res.powq(); res*=res; res*=res;  // res=pow(res,CF);
    
    if (cf<0) res/=powu(w,-cf);
    else res*=powu(w,cf);
 
    if (res==(ZZn6)1) return TRUE;
    return FALSE;   
}

BOOL ecap2(ECn& P,ECn3 Q,ECn& R,ECn3 &S,Big& order,Big& cf)
{
    ECn PP=P;
    ECn RR=R;
    ZZn3 Qx,Qy,Sx,Sy;
    int qnr=-get_mip()->cnr;

    normalise(PP);
    Q.get(Qx,Qy);

// untwist    
    Qx=Qx/qnr;
    Qy=tx(Qy);
    Qy=Qy/(qnr*qnr);

    RR=R;

    normalise(RR);
    S.get(Sx,Sy);

// untwist    
    Sx=Sx/qnr;
    Sy=tx(Sy);
    Sy=Sy/(qnr*qnr);

    return fast_double_tate_pairing(PP,Qx,Qy,RR,Sx,Sy,order,cf);
}

//
// Hash functions
// 

Big H1(char *string,int len)
{ // Hash a zero-terminated string to a number < modulus
    Big h,p;
    char s[HASH_LEN];
    int i,j; 
    sha sh;

    shs_init(&sh);

    for (i=0;i<len;i++)
        shs_process(&sh,string[i]);
    
    shs_hash(&sh,s);
    p=get_modulus();
    h=1; j=0; i=1;
    forever
    {
        h*=256; 
        if (j==HASH_LEN)  {h+=i++; j=0;}
        else         h+=s[j++];
        if (h>=p) break;
    }
    h%=p;
    return h;
}

// Hash and map a Client Identity to a curve point E_(Fp) of order q

ECn hash_and_map(char *ID,int len)
{
    ECn Q;
    Big x0=H1(ID,len);

    while (!Q.set(x0,x0)) x0+=1;
    Q*=CF;
    return Q;
}


int main()
{
    ifstream common("mnt.ecs");      // MNT elliptic curve parameters
    ifstream signature("bls_signature.sig");
    ifstream public_key("bls_public.key");

    miracl* mip=&precision;
    ECn S,HM;
    ECn3 P,R;
    ZZn3 u,v,x3,y3;
    Big a,b,c;
    Big p,q,x,B,cf,cfp;
    int bbits,A,lsb;

    common >> bbits;
    mip->IOBASE=16;
    common >> p;
    common >> A;
    common >> B >> q >> cf;
   
    init_zzn6(p);

    ecurve(A,B,p,MR_PROJECTIVE);
    cfp=cf-CF*p;  // ~ (t-1)
    mip->TWIST=TRUE;   // map to point on twisted curve E(Fp3)

// don't use compression here because it will be slower...

    public_key >> a;
    public_key >> b;
    public_key >> c;

    x3.set(a,b,c);

    public_key >> a;
    public_key >> b;
    public_key >> c;

    y3.set(a,b,c);

    P.set(x3,y3);

    public_key >> a;
    public_key >> b;
    public_key >> c;

    x3.set(a,b,c);

    public_key >> a;
    public_key >> b;
    public_key >> c;

    y3.set(a,b,c);

    R.set(x3,y3);

    signature >> x;
    signature >> lsb;
//cout << "bits(x)= " << bits(x) << endl;
//cout << "x= " << x << endl;
//cout << "lsb= " << lsb << endl;

    if (!S.set(x,1-lsb))
    {
        cout << "Signature is invalid" << endl;
        exit(0);
    }

    HM=hash_and_map("This a quick test of the method",32);

//cout << "HM= " << HM << endl;
//cout << "S= " << S << endl;
//cout << "P= " << P << endl;
//cout << "R= " << R << endl;

    if (ecap2(S,P,HM,R,q,cfp)) cout << "Signature is TRUE" << endl;
    else                       cout << "SIgnature is FALSE" << endl;

    return 0;
}

