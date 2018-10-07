/*
 *   Proposed Digital Signature Standard
 *
 *   Elliptic Curve Variation GF(2^m) - See Dr. Dobbs Journal April 1997
 *
 *   This program generates one set of public and private keys in files 
 *   public.ecs and private.ecs respectively. Notice that the public key 
 *   can be much shorter in this scheme, for the same security level.
 *
 *   It is assumed that Curve parameters are to be found in file common2.ecs
 *
 *   The curve is y^2+xy = x^3+Ax^2+B over GF(2^m) using a trinomial or 
 *   pentanomial basis (t^m+t^a+1 or t^m+t^a+t^b+t^c+1). These parameters
 *   can be generated using the findbase.cpp example program, or taken from tables
 *   provided, for example in IEEE-P1363 Annex A
 *
 *   The file common2.ecs is presumed to exist and contain 
 *   {m,A,B,q,x,y,a,b,c} where A and B are parameters of the equation 
 *   above, (x,y) is an initial point on the curve, {m,a,b,c} are the field 
 *   parameters, (b is zero for a trinomial) and q is the order of the 
 *   (x,y) point, itself a large prime. The number of points on the curve is 
 *   cf.q where cf is the "co-factor", normally 2 or 4.
 * 
 *   Copyright (c) 2000-2003 Shamus Software Ltd.
 */

#include <stdio.h>
#include "miracl.h"

int main()
{
    FILE *fp;
    int ep,m,a,b,c;
    miracl *mip;
    epoint *g,*w;
    big a2,a6,q,x,y,d;
    long seed;
    fp=fopen("common2.ecs","rt");
    if (fp==NULL)
    {
        printf("file common2.ecs does not exist\n");
        return 0;
    }
    fscanf(fp,"%d\n",&m);

    mip=mirsys(MR_ROUNDUP(abs(m),4),16);  /* MR_ROUNDUP rounds up m/MIRACL */
    a2=mirvar(0);
    a6=mirvar(0);
    q=mirvar(0);
    x=mirvar(0);
    y=mirvar(0);
    d=mirvar(0);

    innum(a2,fp);
    innum(a6,fp);
    innum(q,fp);
    innum(x,fp);
    innum(y,fp);

    fscanf(fp,"%d\n",&a);
    fscanf(fp,"%d\n",&b);
    fscanf(fp,"%d\n",&c);
    fclose(fp);

/* randomise */
    printf("Enter 9 digit random number seed  = ");
    scanf("%ld",&seed);
    getchar();
    
    irand(seed);
    ecurve2_init(m,a,b,c,a2,a6,FALSE,MR_BEST);  /* initialise curve */

    g=epoint_init();
    w=epoint_init();

    if (!epoint2_set(x,y,0,g)) /* initialise point of order q */
    {
        printf("Problem - point (x,y) is not on the curve\n");
        return 0;
    }

    ecurve2_mult(q,g,w);

    if (!point_at_infinity(w))
    {
        printf("Problem - point (x,y) is not of order q\n");
        return 0;
    }

/* generate public/private keys */

    bigrand(q,d);

    ecurve2_mult(d,g,g);
    

    ep=epoint2_get(g,x,x); /* compress point */

    printf("public key = %d ",ep);
    otnum(x,stdout);

    fp=fopen("public.ecs","wt");
    fprintf(fp,"%d ",ep);
    otnum(x,fp);
    fclose(fp);

    fp=fopen("private.ecs","wt");
    otnum(d,fp);
    fclose(fp);
    return 0;
}

