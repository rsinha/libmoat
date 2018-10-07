/*
   Boneh-Lynn-Shacham short signature scheme - signature phase
   cl /O2 /GX bls_sign.cpp ecn.cpp big.cpp ms32.lib

   I believe this method is patented - so check first before use in a commercial application
*/

#include <iostream>
#include <fstream>
#include <string.h>
#include "ecn.h"
#include <ctime>

// cofactor - number of points on curve=CF.q

#define CF 4  

using namespace std;

Miracl precision(40,16); 

// Using SHA-1 as basic hash algorithm

#define HASH_LEN 20

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
    ifstream private_key("bls_private.key");
    ofstream signature("bls_signature.sig");
    miracl* mip=&precision;
    ECn PM;
    Big x,s,p,q,B;
    int bits,A,lsb;

    common >> bits;
    mip->IOBASE=16;
    common >> p;
    common >> A;
    common >> B >> q;

    private_key >> s;

    ecurve(A,B,p,MR_PROJECTIVE);

    PM=hash_and_map("This a quick test of the method",32);

    cout << "Short message has been signed - signature in bls_signature.sig " << endl;

    PM*=s;

    lsb=PM.get(x);

    signature << x << endl;
    signature << lsb << endl;

    return 0;
}

