/*
   Scott's AKE Client/Server testbed

   See http://eprint.iacr.org/2002/164

   Compile as 
   cl /O2 /GX /DZZNS=16 ake6t.cpp zzn6.cpp big.cpp zzn.cpp ecn.cpp miracl.lib
   using COMBA build

   This version uses the sextic twist and the Ate pairing
   No elliptic curve operations over an extension field!
  
   p=1+3*x+3*x*x+9*pow(x,3)+27*pow(x,4)
   r=1+3*x+9*x*x
   t=2+3*x

   For this curve k=6, rho=2 (which is bad...)
   p is 512 bits, 6p = 3072 bits, r is 256 bits

   final exponent = (1+9*x^3)*p^0 + 3x^2*p^1

   The file k6.ecs with curve details is required

   Modified to prevent sub-group confinement attack

*/

#include <iostream>
#include <fstream>
#include <string.h>
#include <ctime>
#include "ecn.h"
#include "zzn6.h"

using namespace std;

Miracl precision(16,0); 

// Using SHA-1 as basic hash algorithm

#define HASH_LEN 20

//
// Define one or the other of these
//
// Which is faster depends on the I/M ratio - See imratio.c
// Roughly if I/M ratio > 16 use PROJECTIVE, otherwise use AFFINE
//

//#define AFFINE
#define PROJECTIVE

//
// Tate Pairing Code
//
// Extract ECn point in internal ZZn format
//

void extract(ECn& A,ZZn& x,ZZn& y)
{ 
    x=(A.get_point())->X;
    y=(A.get_point())->Y;
}

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

ZZn6 line(ECn& A,ECn& C,ZZn& slope,ECn& Q)
{ 
    ZZn6 n,w,s;
    ZZn3 p;
    ZZn x,y,z,t,Qx,Qy; 
    extract(Q,Qx,Qy);
#ifdef AFFINE
    extract(A,x,y);
    p.set1(x);
    n.set(p);
    p.set1(y);
    w.seti(p);
    n-=Qx; w-=Qy;
    s.seti(slope);
    n*=s; n-=w;
#endif
#ifdef PROJECTIVE
    extract(A,x,y,z);
    x*=z; t=z; z*=z; z*=t;
    Qx*=z; Qy*=z;
    p.set1(y);
    w.seti(p);
    p.set1(x);
    n.set(p);
    w-=Qy; n-=Qx;

    s.seti(slope);
    n*=s;
    extract(C,x,y,z);
    w*=z; n-=w;
#endif
    return n;
}

//
// Add A=A+B  (or A=A+A) 
// Bump up num
//

ZZn6 g(ECn& A,ECn& B,ECn& Q)
{
    ZZn  lam;
    big ptr;
    ECn P=A;

// Evaluate line from A
    ptr=A.add(B);
    if (ptr==NULL) return (ZZn6)1;
    else lam=ptr;

    return line(P,A,lam,Q);    
}

//
// Tate Pairing - note denominator elimination has been applied
//
// P is a point of order q. Q(x,y) is a point of order m.q. 
// Note that P is a point on the sextic twist curve over Fp, 
// Q(x,y) a point on the base curve 
//

BOOL fast_tate_pairing(ECn& P,ECn& Q,Big& q,Big &x,ZZn3& r)
{ 
    int i,j,n,nb,nbw,nzs;
    ECn A;
    Big T=3*x+1;
    ZZn6 w,t,res;

    res=1;  
    A=P;
    normalise(Q);

    nb=bits(T);

    for (i=nb-2;i>=0;i--)
    {
        res*=res;
        t=g(A,A,Q);
//cout << "t= " << t << endl;
        res*=t; 
        if (bit(T,i))
        {
            t=g(A,P,Q);
            res*=t;
        }
    }

    if (res.iszero()) return FALSE;

    w=res;                          
    w.powq();
    res*=w;                        // ^(p+1)

    w=res;
    w.powq(); w.powq(); w.powq();
    res=w/res;                     // ^(p^3-1)

    t=w=res;
    w.powq();

    res=pow(res,3*x);              // specially tailored final exponentiation
    res*=w;
    res=pow(res,3*x);
    res=pow(res,x);
    res*=t;

    r=real(res);
    if (r==(ZZn3)1) return FALSE;
    return TRUE;            
}

//
// Hash functions
// 

Big H1(char *string)
{ // Hash a zero-terminated string to a number < modulus
    Big h,p;
    char s[HASH_LEN];
    int i,j; 
    sha sh;

    shs_init(&sh);

    for (i=0;;i++)
    {
        if (string[i]==0) break;
        shs_process(&sh,string[i]);
    }
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

Big H2(ZZn3 x)
{ // Hash an Fp6 to a big number
    sha sh;
    Big a,h,p,xx[3];
    ZZn u,v,w;
    char s[HASH_LEN];
    int i,j,m;

    shs_init(&sh);
    x.get(u,v,w);
    xx[0]=u; xx[1]=v; xx[2]=w;
    for (i=0;i<3;i++)
    {
        a=xx[i];
        while (a>0)
        {
            m=a%256;
            shs_process(&sh,m);
            a/=256;
        }
    }
    shs_hash(&sh,s);
    h=from_binary(HASH_LEN,s);
    return h;
}

// Hash and map a Client Identity to a curve point E_(Fp)

ECn hash_and_map(char *ID,Big& cof)
{
    ECn Q;
    Big x0=H1(ID);
    forever
    {
        while (!Q.set(x0)) x0+=1;
        x0+=1;
        Q*=cof;
        if (!Q.iszero()) break;
    }
    return Q;
}

int main()
{
    ifstream common("k6.ecs");      // elliptic curve parameters
    miracl* mip=&precision;
    ECn Alice,Bob,sA,sB,Server,sS;
    ZZn3 res,sp,ap,bp;
    Big a,b,s,ss,p,q,x,y,B,cof,t,cf;
    int i,bits,A;
    time_t seed;

    common >> bits;
    mip->IOBASE=16;
    common >> p;
    common >> A;
    common >> B >> q >> cof >> x;

    init_zzn6(p);
    cout << "Initialised... " << endl;
    cout << "p%24= " << p%24 << endl;
    cout << "cnr= " << mip->cnr << endl;
    time(&seed);
    irand((long)seed);
    mip->IOBASE=16;

    ss=rand(q);    // TA's super-secret 

#ifdef AFFINE
    ecurve(A,B,p,MR_AFFINE);
#endif
#ifdef PROJECTIVE
    ecurve(A,B,p,MR_PROJECTIVE);
#endif

    cout << "Mapping Server ID to point" << endl;
    Server=hash_and_map("Server",cof);
    sS=ss*Server;

// sextic twist

#ifdef AFFINE
    ecurve(A,-B*(p-1)/2,p,MR_AFFINE);
#endif
#ifdef PROJECTIVE
    ecurve(A,-B*(p-1)/2,p,MR_PROJECTIVE);
#endif

    cout << "Mapping Alice & Bob ID's to points" << endl;
    Alice=hash_and_map("Alice",cof+1);  // cof+1 is the co-factor for the sextic twist (?)
    Bob=  hash_and_map("Robert",cof+1);

    cout << "Alice and Bob visit Trusted Authority" << endl; 

    sA=ss*Alice; 
    sB=ss*Bob; 

    cout << "Alice and Server Key Exchange" << endl;

    a=rand(q);   // Alice's random number
    s=rand(q);   // Server's random number

    if (!fast_tate_pairing(sA,Server,q,x,res)) cout << "Trouble" << endl;
    if (powl(res,q)!=(ZZn3)1)
    {
        cout << "Wrong group order - aborting" << endl;
        exit(0);
    }
    ap=powl(res,a);

    if (!fast_tate_pairing(Alice,sS,q,x,res)) cout << "Trouble" << endl;
    if (powl(res,q)!=(ZZn3)1)
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

    if (!fast_tate_pairing(sB,Server,q,x,res)) cout << "Trouble" << endl;
    if (powl(res,q)!=(ZZn3)1)
    {
        cout << "Wrong group order - aborting" << endl;
        exit(0);
    }
    bp=powl(res,b);

    if (!fast_tate_pairing(Bob,sS,q,x,res)) cout << "Trouble" << endl;
    if (powl(res,q)!=(ZZn3)1)
    {
        cout << "Wrong group order - aborting" << endl;
        exit(0);
    }
    sp=powl(res,s);

    cout << "Bob's  Key= " << H2(powl(sp,b)) << endl;
    cout << "Server Key= " << H2(powl(bp,s)) << endl;

    cout << "Alice and Bob's attempted Key exchange" << endl;

    if (!fast_tate_pairing(Alice,sB,q,x,res)) cout << "Trouble" << endl;
    if (powl(res,q)!=(ZZn3)1)
    {
        cout << "Wrong group order - aborting" << endl;
        exit(0);
    }
    bp=powl(res,b);

    if (!fast_tate_pairing(sA,Bob,q,x,res)) cout << "Trouble" << endl;
    if (powl(res,q)!=(ZZn3)1)
    {
        cout << "Wrong group order - aborting" << endl;
        exit(0);
    }
    ap=powl(res,a);

    cout << "Alice  Key= " << H2(powl(ap,b)) << endl;
    cout << "Bob's Key=  " << H2(powl(bp,a)) << endl;

    return 0;
}

