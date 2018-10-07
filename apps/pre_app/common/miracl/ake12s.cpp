/*
   Scott's AKE Client/Server testbed

   See http://eprint.iacr.org/2002/164

   Compile as 
   cl /O2 /GX /DZZNS=12 ake12s.cpp zzn12.cpp zzn6a.cpp ecn2.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.lib
   using COMBA build

   The curve generated is generated from a 64-bit x parameter
   This version implements that Ate pairing

   This is implemented on the Barreto-Lynn-Scott k=12, rho=1.5 pairing friendly curve

   NOTE: Irreducible polynomial is of the form x^6+sqrt(-2)

   See blsk12.cpp for a program to generate suitable curves

   Modified to prevent sub-group confinement attack
*/

#include <iostream>
#include <fstream>
#include <string.h>
#include "ecn.h"
#include <ctime>
#include "ecn2.h"
#include "zzn12.h"

using namespace std;

Miracl precision(16,0); 
/*
extern "C"
{
    int fpc=0;
    int fpa=0;
}
*/

//#define AFFINE
#define PROJECTIVE

// Using SHA-256 as basic hash algorithm

#define HASH_LEN 32

//
// Ate Pairing Code
//

void set_frobenius_constant(ZZn12 &X)
{
    ZZn12 x;
    Big p=get_modulus();
    x.seti((ZZn6)1);
    X=pow(x,p);
}

//
// Line from A to destination C. Let A=(x,y)
// Line Y-slope.X-c=0, through A, so intercept c=y-slope.x
// Line Y-slope.X-y+slope.x = (Y-y)-slope.(X-x) = 0
// Now evaluate at Q -> return (Qy-y)-slope.(Qx-x)
//

ZZn12 line(ECn2& A,ECn2& C,ZZn2& slope,ZZn& Qx,ZZn& Qy)
{
     ZZn12 w;
     ZZn6 nn,dd;
     ZZn2 X,Y;
#ifdef AFFINE
     A.get(X,Y);

     dd.set(slope*Qx,Y-slope*X);
     nn.set((ZZn2)-Qy);
     w.set(nn,dd);

#endif
#ifdef PROJECTIVE
    ZZn2 Z,Z2,ZZ,ZZZ;

    A.get(X,Y,Z);
    C.getZ(Z2);

    ZZ=Z*Z;
    ZZZ=ZZ*Z;

    dd.set((ZZZ*slope)*Qx,Z2*Y-Z*X*slope);
    nn.set((ZZn2)-(ZZZ*Z2)*Qy);
    w.set(nn,dd);

#endif
     return w;
}

//
// Add A=A+B  (or A=A+A) 
// Return line function value
//

ZZn12 g(ECn2& A,ECn2& B,ZZn& Qx,ZZn& Qy)
{
    ZZn2 lam;
    ZZn12 r;
    ECn2 P=A;

// Evaluate line from A
    A.add(B,lam);
    if (A.iszero())   return (ZZn12)1; 

    r=line(P,A,lam,Qx,Qy);
//cout << "r= " << r << endl;
    return r;
}

//
// Ate Pairing - note denominator elimination has been applied
//
// P is a point of order q. Q(x,y) is a point of order q. 
// Note that P is a point on the sextic twist of the curve over Fp^2, Q(x,y) is a point on the 
// curve over the base field Fp
//

BOOL fast_tate_pairing(ECn2& P,ZZn& Qx,ZZn& Qy,Big &x,ZZn12 &X,ZZn6& res)
{ 
    ECn2 A;
    int i,nb;
    Big n;
    ZZn12 w,r,a,b,c,rp;

    n=3*x+1;       // t-1
    A=P;           // remember A
 
    nb=bits(n);
    r=1;
//fpc=fpa=0;
    for (i=nb-2;i>=0;i--)
    {
        r*=r;   
        r*=g(A,A,Qx,Qy); 
 
        if (bit(n,i)) 
            r*=g(A,P,Qx,Qy);  
    }

//cout << "Miller fpa= " << fpa << endl;
//cout << "Miller fpc= " << fpc << endl;
//fpa=fpc=0;

    if (r.iszero()) return FALSE;

    w=r;

    r.conj();
    r/=w;    // r^(p^6-1)

    w=r;
    r.powq(X); r.powq(X);
    r*=w;    // r^[(p^6-1)*(p^2+1)]

// New idea..

// Calculate final exponentiation 
// Does not require multi-exponentiation, but total exponent length is the same.
// Also does not need precomputation (x is sparse). 
//

    a=pow(r,3*x);   // A = r^{3x}
    a=pow(a,x);     // A = r^(3x^2)
    b=a;          
    b.powq(X);      
    b.powq(X);      // A^{p^2}
    rp=r*b;         // r.A^{p^2}
    b.powq(X);
    rp*=b;          // r.A^{p^2}.A^{p^3}
    a=pow(a,3*x);   // B = A^{3*x}
    b=a;
    b.powq(X);
    b.powq(X);
    rp*=b;          // r.A^{p^2}.A^{p^3}*B^{p^2}
    w=(a*a);
    rp*=w;          // r.A^{p^2}.A^{p^3}*B^{p^2}.B^2
    w.powq(X);
    rp*=w;          // r.A^{p^2}.A^{p^3}*B^{p^2}.B^2.(B^2)^p
    a=pow(a,3*x);   // C=B^{3*x}
    b=a;  
    b.powq(X);
    rp*=b;          // r.A^{p^2}.A^{p^3}*B^{p^2}.B^2.(B^2)^p.C^p
    b=a*a*a;        
    rp*=b;          // r.A^{p^2}.A^{p^3}*B^{p^2}.B^2.(B^2)^p.C^p.C^3
    a=pow(a,3*x);
    r=rp*a;         // r.A^{p^2}.A^{p^3}*B^{p^2}.B^2.(B^2)^p.C^p.C^3.C^{3*x}
//cout << "FE fpc= " << fpc << endl;
//cout << "FE fpa= " << fpa << endl;
//fpa=fpc=0;
    res= real(r);                    // compress to half size...
    return TRUE;
}

//
// ecap(.) function
//

BOOL ecap(ECn2& P,ECn& Q,Big& x,ZZn12 &X,ZZn6& r)
{
    BOOL Ok;
    Big xx,yy;
    ZZn Qx,Qy;

    Q.get(xx,yy); Qx=xx; Qy=yy;

    Ok=fast_tate_pairing(P,Qx,Qy,x,X,r);

    if (Ok) return TRUE;
    return FALSE;
}

//
// Hash functions
// 

Big H1(char *string)
{ // Hash a zero-terminated string to a number < modulus
    Big h,p;
    char s[HASH_LEN];
    int i,j; 
    sha256 sh;

    shs256_init(&sh);

    for (i=0;;i++)
    {
        if (string[i]==0) break;
        shs256_process(&sh,string[i]);
    }
    shs256_hash(&sh,s);
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

Big H2(ZZn6 x)
{ // Hash an Fp6 to a big number
    sha256 sh;
    ZZn2 u,v,w;
    ZZn h,l;
    Big a,hash,p,xx[6];
    char s[HASH_LEN];
    int i,j,m;

    shs256_init(&sh);
    x.get(u,v,w);
    u.get(l,h);
    xx[0]=l; xx[1]=h;
    v.get(l,h);
    xx[2]=l; xx[3]=h;
    w.get(l,h);
    xx[4]=l; xx[5]=h;

    for (i=0;i<6;i++)
    {
        a=xx[i];
        while (a>0)
        {
            m=a%256;
            shs256_process(&sh,m);
            a/=256;
        }
    }
    shs256_hash(&sh,s);
    hash=from_binary(HASH_LEN,s);
    return hash;
}

// Hash and map a Server Identity to a curve point E_(Fp2)

ECn2 hash_and_map2(char *ID,Big cf)
{
    int i;
    ECn2 S,SS;
    ZZn2 X;
 
    Big x0=H1(ID);

    forever
    {
        x0+=1;
        X.set((ZZn)1,(ZZn)x0);
        if (!S.set(X)) continue;
        break;
    }
    S*=cf;
    S.norm();

    return S;
}     

// Hash and map a Client Identity to a curve point E_(Fp) of order q

ECn hash_and_map(char *ID)
{
    ECn Q;
    Big x0=H1(ID);

    while (!Q.set(x0,x0)) x0+=1;
   
    return Q;
}

int main()
{
    miracl* mip=&precision;
    ECn Alice,Bob,sA,sB;
    ECn2 Server,sS;
    ZZn6 sp,ap,bp,res;
    ZZn12 X;
    Big a,b,s,ss,p,q,x,y,B,cf,t;
    int i,bits,A;
    time_t seed;

    mip->IOBASE=16;
    x= "480000000017B576";  // found by BLSK12.CPP
    
    p=243*pow(x,6)+324*pow(x,5)+135*pow(x,4)+18*pow(x,3)+3*x*x+3*x+1;
    t=3*x+2;
    q=81*pow(x,4)+108*pow(x,3)+45*x*x+6*x+1;
    cf=3*x*x*(p+t)+1;
    modulo(p);
    set_frobenius_constant(X);

    cout << "Initialised... " << endl;

    time(&seed);
    irand((long)seed);

#ifdef AFFINE
    ecurve((Big)0,(Big)1,p,MR_AFFINE);
#endif
#ifdef PROJECTIVE
    ecurve((Big)0,(Big)1,p,MR_PROJECTIVE);
#endif
    mip->IOBASE=16;
    mip->TWIST=TRUE;   // map Server to point on twisted curve E(Fp2)

    ss=rand(q);    // TA's super-secret 

    cout << "Mapping Server ID to point" << endl;
    Server=hash_and_map2("Server",cf);

    cout << "Mapping Alice & Bob ID's to points" << endl;
    Alice=hash_and_map("Alice");
    Bob=  hash_and_map("Robert");

    cout << "Alice, Bob and the Server visit Trusted Authority" << endl; 

    sS=ss*Server; 
    sS.norm();
    sA=ss*Alice; 
    sB=ss*Bob; 

    cout << "Alice and Server Key Exchange" << endl;

    a=rand(q);   // Alice's random number
    s=rand(q);   // Server's random number

 //   for (i=0;i<1000;i++)
   
    if (!ecap(Server,sA,x,X,res)) cout << "Trouble" << endl;
    if (powl(res,q)!=(ZZn6)1)
    {
        cout << "Wrong group order - aborting" << endl;
        exit(0);
    }
    ap=powl(res,a);

    if (!ecap(sS,Alice,x,X,res)) cout << "Trouble" << endl;
    if (powl(res,q)!=(ZZn6)1)
    {
        cout << "Wrong group order - aborting" << endl;
        exit(0);
    }
    sp=powl(res,s);

    cout << "Alice  Key= " << H2(powl(sp,a)) << endl;
    cout << "Server Key= " << H2(powl(ap,s)) << endl;

    cout << "Bob and Server Key Exchange" << endl;

    b=rand(q);   // Bob's random number
    s=rand(q);   // Server's random number

    if (!ecap(Server,sB,x,X,res)) cout << "Trouble" << endl;
    if (powl(res,q)!=(ZZn6)1)
    {
        cout << "Wrong group order - aborting" << endl;
        exit(0);
    }
    bp=powl(res,b);

    if (!ecap(sS,Bob,x,X,res)) cout << "Trouble" << endl;
    if (powl(res,q)!=(ZZn6)1)
    {
        cout << "Wrong group order - aborting" << endl;
        exit(0);
    }
    sp=powl(res,s);

    cout << "Bob's  Key= " << H2(powl(sp,b)) << endl;
    cout << "Server Key= " << H2(powl(bp,s)) << endl;

    return 0;
}

