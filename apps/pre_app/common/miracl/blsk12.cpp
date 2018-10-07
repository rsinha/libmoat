//
// cl /O2 /GX blsk12.cpp zzn12.cpp zzn6a.cpp zzn2.cpp zzn.cpp ecn2.cpp ecn.cpp big.cpp ms32.lib
// Program to generate Barreto-Lynn-Scott k=12 rho=1.5 curves for use by ake12s.cpp
//

#include <iostream>
#include "big.h"
#include "ecn.h"
#include "ecn2.h"
#include "zzn12.h"

using namespace std;

Miracl precision=100;

//
// Hash functions
// 

#define HASH_LEN 32


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


int main()
{
    int ns,twist;
    int sign;
    BOOL ontwist;
    Big cof,r,m1,m2,n,p,t,x,cube,y,b,eta,w,cf[4];
    Big PP,TT,FF;
    miracl*mip=&precision;
    ECn P;
    ECn2 Q;
    ZZn2 x2,y2,xi;
    ZZn12 X,Y;
    ZZn6 A,B;
    
//    mip->IOBASE=16;

    x=pow((Big)2,62)+pow((Big)2,59);  // x is this size to get right size for t, p and n
                                        // x is low hamming weight
    mip->IOBASE=16;
    sign=1;  // 1= positive, 2=negative for +/- x solutions
    ns=1;
    forever
    {
        forever
        {
     //       sign=3-sign;   // always looking for +ve x solutions.
            if (sign==1) x+=1;
          
            if (sign==1) p=243*pow(x,6)+324*pow(x,5)+135*pow(x,4)+18*pow(x,3)+3*x*x+3*x+1;
            else         p=243*pow(x,6)-324*pow(x,5)+135*pow(x,4)-18*pow(x,3)+3*x*x-3*x+1;

            if (p%8==1) continue;
            if (p%9==1) continue;
           
            if (p%6!=1) continue;   // check congruence conditions
   
            if (!prime(p)) continue;
            modulo(p);
            if (p%8==5) xi.set(0,1);
            else        xi.set(1,1);
            if (pow(xi,(p-1)/2)==1) continue;
            if (pow(xi,(p-1)/3)==1) continue;  // make sure that x^6+c is irreducible

            if (sign==1) t=3*x+2;
			else         t=-3*x+2;
			n=p+1-t;
			if (sign==1) r=81*pow(x,4)+108*pow(x,3)+45*x*x+6*x+1;
			else         r=81*pow(x,4)-108*pow(x,3)+45*x*x-6*x+1;

			if (prime(r))  break;

        }     
        
        cof=n/r;

        cf[3]=3*x*x;
        cf[2]=9*x*x*x+3*x*x;
        cf[1]=36*x*x*x*x+18*x*x*x;
        cf[0]=81*x*x*x*x*x+81*x*x*x*x+18*x*x*x+1;

// find number of points on sextic twist..

        TT=t*t-2*p;
        PP=p*p;

        FF=sqrt((4*PP-TT*TT)/3);

        m1=PP+1-(-3*FF+TT)/2;  // 2 possibilities...
        m2=PP+1-(3*FF+TT)/2;

        if (m2%n==0)
        {
            cout << "something puzzling happened!" << endl;
            exit(0);
        }


        b=0;
        forever
        {
            b+=1;
            ecurve(0,b,p,MR_AFFINE);
            while (!P.set(rand(p))) ;
            if ((n*P).iszero()) break; // wrong curve
        }

        P*=cof;

        mip->TWIST=TRUE;
        while (!Q.set(randn2())) ;

        ontwist=FALSE;
        if ((m1*Q).iszero()) 
        {
            Q*=m1/r;
            ontwist=TRUE;  
            twist=1;
        }
        else if ((m2*Q).iszero())
        {
            Q*=(m2/r);
//            ontwist=TRUE;  // always wrong order!
            twist=2;
        }
        
        if (!ontwist) continue;

        if (!(r*Q).iszero())
        {
            cout << "something badly wrong" << endl;
            exit(0);
        }

        Q.get(x2,y2);
        A.set((ZZn2)0,x2,(ZZn2)0);
        B.set((ZZn2)0,y2,(ZZn2)0);
        X.set(A); Y.set((ZZn6)0,B);

        if (Y*Y!=X*X*X +(ZZn12)b) continue;

        cout << "solution " << ns << endl;
        cout << "irreducible polynomial = X^6 + " << xi << endl;
        cout << "p=" << p << endl;
        cout << "p mod 72 = " << p%72 << endl;
        cout << "x mod 72 = " << x%72 << endl;
        if (sign==1) cout << "x= +" << x << endl;
        else         cout << "x= -" << x << endl;
        cout << "bits(p)= " << bits(p) << endl;
        cout << "r=" << r << endl;
        cout << "t=" << t << endl;
        cout << "cof= " << m2/r << endl;
        cout << "coefficients of (p^4-p^2+1)/n to base p" << endl; 
        cout << "cf[0]= " << cf[0] << endl;
        cout << "cf[1]= " << cf[1] << endl;
        cout << "cf[2]= " << cf[2] << endl;
        cout << "cf[3]= " << cf[3] << endl;
        cout << "bits(t)= " << bits(t) << endl;
        cout << "ham(t-1) = " << ham(t-1) << " (small is better for Ate pairing)" << endl;
        cout << "bits(r)= " << bits(r) << endl;
        cout << "ham(r-1) = " << ham(r-1) << " (small is better for Tate pairing)" << endl;
        cout << "Twist= " << twist << endl;
        cout << "p%8= " << p%8 << endl;
        cout << "E(Fp): y^2=x^3+" << b << endl;
        cout << "Point P= " << P << endl;
        cout << "Point Q= " << Q << endl << endl;
        ns++;

        if (ns==50) break;
    }
    return 0;
}

