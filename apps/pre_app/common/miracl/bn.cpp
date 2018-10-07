//
// cl /O2 /GX bn.cpp zzn12.cpp zzn6a.cpp zzn2.cpp zzn.cpp ecn2.cpp ecn.cpp big.cpp ms32.lib
// Program to generate BN curves for use by ake12t.cpp and ake12.cpp
//

#include <iostream>
#include "big.h"
#include "ecn.h"
#include "ecn2.h"
#include "zzn12.h"

using namespace std;

Miracl precision=100;

int main()
{
    int ns;
    int sign;
    BOOL ontwist;
    Big m1,m2,n,p,t,x,cube,y,b,eta,w,cf[4];
    Big PP,TT,FF;
    miracl*mip=&precision;
    ECn P;
    ECn2 Q;
    ZZn2 x2,y2,xi;
    ZZn12 X,Y;
    ZZn6 A,B;
    
//    mip->IOBASE=16;

    x=pow((Big)2,62)+pow((Big)2,61)-1;  // x is this size to get right size for t, p and n
                                        // x is low hamming weight
    mip->IOBASE=16;
    sign=1;  // 1= positive, 2=negative for +/- x solutions
    ns=1;
    forever
    {
        forever
        {
        //    sign=3-sign;    // always looking for +ve x solutions.
            if (sign==1) x+=1;
          
            if (sign==1) p=36*pow(x,4)-36*pow(x,3)+24*x*x-6*x+1;
            else         p=36*pow(x,4)+36*pow(x,3)+24*x*x+6*x+1;

            if (p%8==1) continue;
            if (p%9==1) continue;
            if (p%6!=1) continue;   // check congruence conditions
           
            if (!prime(p)) continue;
            modulo(p);
            if (p%8==5) xi.set(0,1);
            else        xi.set(1,1);
            if (pow(xi,(p-1)/2)==1) continue;
            if (pow(xi,(p-1)/3)==1) continue;  // make sure that x^6+c is irreducible

            t=6*x*x+1;
            n=p+1-t;
            if (prime(n)) break;
        }     
        
        cf[3]=1;
        cf[2]=6*x*x+1;
        cf[1]=36*x*x*x-18*x*x+12*x+1;
        cf[0]=36*x*x*x-30*x*x+18*x-2;

// find number of points on sextic twist..

        TT=t*t-2*p;
        PP=p*p;

        FF=sqrt((4*PP-TT*TT)/3);

        m1=PP+1-(-3*FF+TT)/2;  // 2 possibilities...
        m2=PP+1-(3*FF+TT)/2;

        if (m1%n==0)
        {
            cout << "something puzzling happened!" << endl;
            exit(0);
        }

        b=2;
        forever
        {
            forever
            {
                b+=1;
                y=sqrt((b+1),p);
                if (y==0) continue;
                break;
            }
            ecurve(0,b,p,MR_AFFINE);

            P.set(1,y);
            if ((n*P).iszero()) break;
        }

        mip->TWIST=TRUE;
        while (!Q.set(randn2())) ;

        ontwist=FALSE;
        if ((m1*Q).iszero()) 
        {
            Q*=m1/n;
 //           ontwist=TRUE;  // always wrong order!
        }
        else if ((m2*Q).iszero())
        {
            Q*=m2/n;
            ontwist=TRUE;
        }
        
        if (!ontwist) continue;
       
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
        cout << "n=" << n << endl;
        cout << "t=" << t << endl;
        cout << "coefficients of (p^4-p^2+1)/n to base p" << endl; 
        cout << "cf[0]= " << cf[0] << endl;
        cout << "cf[1]= " << cf[1] << endl;
        cout << "cf[2]=                  " << cf[2] << endl;
        cout << "cf[3]= " << cf[3] << endl;
        cout << "bits(t)= " << bits(t) << endl;
        cout << "ham(t-1) = " << ham(t-1) << " (small is better for Ate pairing)" << endl;
     //   cout << "ham(6*x)+ham(x)+1 = " << ham(6*x)+ham(x)+1 << endl;
     //   cout << "ham(6*x*x+1) = " << ham(6*x*x+1) << endl;
     //   if (ham(6*x)+ham(x)+1 > ham(6*x*x+1)) break;
        
        cout << "bits(n)= " << bits(n) << endl;
        cout << "ham(n-1) = " << ham(n-1) << " (small is better for Tate pairing)" << endl;

        cout << "E(Fp): y^2=x^3+" << b << endl;
        cout << "Point P= " << P << endl;
        cout << "Point Q= " << Q << endl << endl;
        ns++;

    }
    return 0;
}

