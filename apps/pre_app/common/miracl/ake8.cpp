/*
   Scott's AKE Client/Server testbed

   See http://www.compapp.dcu.ie/research/CA_Working_Papers/wp02.html#0202

   Compile as 
   cl /O2 /GX /DZZNS=16 ake8.cpp zzn8.cpp zzn4.cpp zzn2.cpp ecn4.cpp big.cpp zzn.cpp 
   ecn.cpp miracl.lib
   Fastest using COMBA build for 512-bit mod-mul

   The file k8.ecs is required 
   Security is G224/F4096  (224-bit group, 4096-bit field)

   Modified to prevent sub-group confinement attack

   **** NEW **** Based on the observation by R. Granger and D. Page and N.P. Smart  in "High Security 
   Pairing-Based Cryptography Revisited" that multi-exponentiation can be used for the final exponentiation
   of the Tate pairing, we suggest the Power Pairing, which calculates E(P,Q,e) = e(P,Q)^e, where the 
   exponentiation by e is basically for free, as it can be folded into the multi-exponentiation.

   NOTE: Irreducible polynomial is x^8+2 : p = 5 mod 8

*/

#include <iostream>
#include <fstream>
#include <string.h>
#include "ecn.h"
#include <ctime>
#include "ecn4.h"
#include "zzn8.h"

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

// #define AFFINE
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

ZZn8 line(ECn& A,ECn& C,ZZn& slope,ZZn4& Qx,ZZn4& Qy)
{ 
    ZZn8 w;
    ZZn4 m=Qx;
    ZZn x,y,z,t;
#ifdef AFFINE
    extract(A,x,y);
    m-=x; m*=slope;  
    w.set((ZZn4)-y,Qy); w-=m;
#endif
#ifdef PROJECTIVE
    extract(A,x,y,z);
    x*=z; t=z; z*=z; z*=t;      
      
    x*=slope; t=slope*z;
    m*=t; m-=x; t=z;
    extract(C,x,x,z);
    m+=(z*y); t*=z;
    w.set(m,-Qy*t);

#endif
    return w;
}

//
// Add A=A+B  (or A=A+A) 
// Bump up num
//

ZZn8 g(ECn& A,ECn& B,ZZn4& Qx,ZZn4& Qy)
{
    ZZn  lam;
    big ptr;
    ECn P=A;

// Evaluate line from A
    ptr=A.add(B);
    if (A.iszero())   return (ZZn8)1; 
    if (ptr==NULL)    return (ZZn8)0;

    lam=ptr;
    return line(P,A,lam,Qx,Qy);
}

void untwist(ECn4& P,ZZn4& U,ZZn4& V)
{
    ZZn2 x,y;

    P.get(U,V);
    U=tx(U);
    U.get(x,y);
    U.set(tx(x),tx(y));   // Qx=-2.i^6.Qx, i is 8th root of -2
    U=-U/2;
    V.get(x,y);
    V.set(tx(x),tx(y));   // Qy=-2.i^4.Qy
    V=-V/2;
}

//
// Tate Pairing - note denominator elimination has been applied
//
// P is a point of order q. Q(x,y) is a point of order m.q. 
// Note that P is a point on the curve over Fp, Q(x,y) a point on the 
// extension field Fp^2
//
// New! Power Pairing calculates E(P,Q,e) = e(P,Q)^e at no extra cost!
//

BOOL power_tate(ECn& P,ECn4 Q,Big& q,Big *cf,ZZn4 &Fr,Big &e,ZZn4& r)
{ 
    int i,nb;
    ECn A;
    ZZn8 w,res,a[4];
    ZZn4 Qx,Qy;
    ZZn2 x,y;
    Big carry,ex[4];
    Big p=get_modulus();

    untwist(Q,Qx,Qy);

    res=1;  

/* Left to right method  */
    A=P;
    nb=bits(q);
    for (i=nb-2;i>=0;i--)
    {
        res*=res;           
        res*=g(A,A,Qx,Qy); 
        if (bit(q,i))
            res*=g(A,P,Qx,Qy);
    }
    if (!A.iszero() || res.iszero()) return FALSE;
    w=res;

    w.powq(Fr); w.powq(Fr);  // ^(p^4-1)
    w.powq(Fr); w.powq(Fr);  
    res=w/res;

    a[3]=res;
    a[2]=a[3]; a[2].powq(Fr);
    a[1]=a[2]; a[1].powq(Fr);
    a[0]=a[1]; a[0].powq(Fr);

    if (e.isone()) for (i=0;i<4;i++) ex[i]=cf[i];
    else
    { // cf *= e
        carry=0;
        for (i=3;i>=0;i--)
            carry=mad(cf[i],e,carry,p,ex[i]);
    }

    res=pow(4,a,ex);
    r=real(res); // compression

//    r=powl(real(res),cf);    // ^(p*p*p*p+1)/q

    if (r.isunity()) return FALSE;
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

Big H4(ZZn4 x)
{ // Hash an Fp2 to a big number
    sha sh;
    Big a,u,v;
    ZZn2 X,Y;
    char s[HASH_LEN];
    int m;

    shs_init(&sh);
    x.get(X,Y);

    X.get(u,v);

    a=u;
    while (a>0)
    {
        m=a%256;
        shs_process(&sh,m);
        a/=256;
    }
    a=v;
    while (a>0)
    {
        m=a%256;
        shs_process(&sh,m);
        a/=256;
    }

    Y.get(u,v);

    a=u;
    while (a>0)
    {
        m=a%256;
        shs_process(&sh,m);
        a/=256;
    }
    a=v;
    while (a>0)
    {
        m=a%256;
        shs_process(&sh,m);
        a/=256;
    }
    shs_hash(&sh,s);
    a=from_binary(HASH_LEN,s);
    return a;
}

// Hash and map a Server Identity to a curve point E(Fp4)

ECn4 hash4(char *ID)
{
    ECn4 T;
    ZZn4 x;
    ZZn2 X,Y=0;
    Big x0,y0=0;

    x0=H1(ID);
    do
    {
        X.set(x0,y0);
        x.set(X,Y);
        x0+=1;
    }
    while (!is_on_curve(x));
    T.set(x);
    return T;
}     

// Hash and map a Client Identity to a curve point E(Fp)

ECn hash_and_map(char *ID,Big cof)
{
    ECn Q;
    Big x0=H1(ID);

    while (!is_on_curve(x0)) x0+=1;
    Q.set(x0);  // Make sure its on E(F_p)

    Q*=cof;
    return Q;
}

ZZn4 get_frobenius_constant()
{
    ZZn4 Fr;
    Big p=get_modulus();
    switch (get_mip()->pmod8)
    {
    case 5:
         Fr.set((ZZn2)0,(ZZn2)1); // = (sqrt(sqrt(-2))^(p-1)/2     
         break;
    case 3:  
    case 7:                                                       
    default: break;
    }
    return pow(Fr,(p-1)/2);
}

int main()
{
    ifstream common("k8.ecs");      // elliptic curve parameters
    miracl* mip=&precision;
    ECn Alice,Bob,sA,sB;
    ECn4 Server,sS;
    ZZn4 res,sp,ap,bp,Fr;
    Big a,b,s,ss,p,q,B,cof;
    Big cf[4];                        
    int i,bitz,A;
    time_t seed;

    cout << "Started" << endl;
    common >> bitz;
    mip->IOBASE=16;
    common >> p;
    common >> A;
    common >> B;
    common >> cof;   // #E/q
    common >> q;     // low hamming weight q
    common >> cf[0];    // [(p^4+1)/q]/(p*p*p)
    common >> cf[1];    // [(p^4+1)/q]/(p*p)
    common >> cf[2];    // [(p^4+1)/q]/p
    common >> cf[3];    // [(p^4+1)/q]%p

    cout << "Initialised... " << endl;

    time(&seed);
    irand((long)seed);

#ifdef AFFINE
    ecurve(A,B,p,MR_AFFINE);
#endif
#ifdef PROJECTIVE
    ecurve(A,B,p,MR_PROJECTIVE);
#endif

    Fr=get_frobenius_constant();

    mip->IOBASE=16;
    mip->TWIST=TRUE;   // map Server to point on twisted curve E(Fp2)

// hash Identities to curve point

    ss=rand(q);    // TA's super-secret 

    cout << "Mapping Server ID to point" << endl;
    Server=hash4("Server");

    cout << "Mapping Alice & Bob ID's to points" << endl;
    Alice=hash_and_map("Alice",cof);

    Bob=  hash_and_map("Robert",cof);

    cout << "Alice, Bob and the Server visit Trusted Authority" << endl; 

    sS=ss*Server; 

    sA=ss*Alice; 
    sB=ss*Bob; 

    cout << "Alice and Server Key Exchange" << endl;

    a=rand(q);   // Alice's random number
    s=rand(q);   // Server's random number

    if (!power_tate(sA,Server,q,cf,Fr,a,res)) cout << "Trouble" << endl;

    if (powl(res,q)!=(ZZn4)1)
    {
        cout << "Wrong group order - aborting" << endl;
        exit(0);
    }
//    ap=powl(res,a);
    ap=res;

    if (!power_tate(Alice,sS,q,cf,Fr,s,res)) cout << "Trouble" << endl;
    if (powl(res,q)!=(ZZn4)1)
    {
        cout << "Wrong group order - aborting" << endl;
        exit(0);
    }
//    sp=powl(res,s);
    sp=res;

    cout << "Alice  Key= " << H4(powl(sp,a)) << endl;
    cout << "Server Key= " << H4(powl(ap,s)) << endl;

    cout << "Bob and Server Key Exchange" << endl;

    b=rand(q);   // Bob's random number
    s=rand(q);   // Server's random number

    if (!power_tate(sB,Server,q,cf,Fr,b,res)) cout << "Trouble" << endl;
    if (powl(res,q)!=(ZZn4)1)
    {
        cout << "Wrong group order - aborting" << endl;
        exit(0);
    }
//    bp=powl(res,b);
    bp=res;

    if (!power_tate(Bob,sS,q,cf,Fr,s,res)) cout << "Trouble" << endl;
    if (powl(res,q)!=(ZZn4)1)
    {
        cout << "Wrong group order - aborting" << endl;
        exit(0);
    }
//    sp=powl(res,s);
    sp=res;

    cout << "Bob's  Key= " << H4(powl(sp,b)) << endl;
    cout << "Server Key= " << H4(powl(bp,s)) << endl;

    return 0;
}

