/* mex.c
 *
 * Updated to allow emission of scheduled code. 
 *
 * Macro EXpansion program.
 * Expands Macros from a .mcs file into a .tpl file to create a .c file
 *
 *  Copyright (c) 2002 Shamus Software Ltd.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int BOOL;
#define FALSE 0
#define TRUE 1

/* Define Algorithms */

#define MULTIPLY 0
#define MULTUP 1
#define SQUARE 2
#define REDC 3
#define ADDITION 4
#define INCREMENT 5
#define SUBTRACTION 6
#define DECREMENT 7
#define SUMMATION 8
#define INCREMENTATION 9
#define DECREMENTATION 10
#define MULTIPLY2 11
#define ADDITION2 12
#define SUBTRACTION2 13
#define PMULT 14


/* Define Macros */

#define MUL_START       0
#define STEP            1
#define STEP1M          2
#define STEP1A          3
#define STEP2M          4
#define STEP2A          5
#define MFIN            6
#define MUL_END         7
#define LAST            8
#define SQR_START       9
#define DSTEP           10
#define DSTEP1M         11
#define DSTEP1A         12
#define DSTEP2M         13
#define DSTEP2A         14
#define SELF            15
#define SFIN            16
#define SQR_END         17
#define REDC_START      18
#define RFINU           19
#define RFIND           20
#define REDC_END        21
#define ADD_START       22
#define ADD             23
#define ADD_END         24
#define SUB_START       25
#define SUB             26
#define SUB_END         27
#define INC_START       28
#define INC             29
#define INC_END         30
#define DEC_START       31
#define DEC             32
#define DEC_END         33
#define KADD_START      34
#define KASL            35
#define KADD_END        36
#define KINC_START      37
#define KIDL            38
#define KINC_END        39
#define KDEC_START      40
#define KDEC_END        41
#define STEPB           42
#define STEPB1M         43
#define STEPB1A         44
#define STEPB2M         45
#define STEPB2A         46
#define H2_MUL_START    47
#define H2_STEP         48
#define H2_MFIN         49
#define H2_MUL_END      50
#define H2_SQR_START    51
#define H2_DSTEP        52
#define H2_SELF         53
#define H2_SFIN         54
#define H2_SQR_END      55
#define H4_MUL_START    56
#define H4_STEP         57
#define H4_MFIN         58
#define H4_MUL_END      59
#define H4_SQR_START    60
#define H4_DSTEP        61
#define H4_SELF         62
#define H4_SFIN         63
#define H4_SQR_END      64
#define H2_LAST         65
#define H4_LAST         66 
#define PMUL_START      67
#define PMUL            68
#define PMUL_END        69
#define MULB_START      70
#define MULB_END        71
#define MBFIN           72
#define H2_MULB_START   73
#define H2_MULB_END     74
#define H2_MBFIN        75
#define H2_STEPB        76
#define H4_MULB_START   77
#define H4_MULB_END     78
#define H4_MBFIN        79
#define H4_STEPB        80
#define LAST_ONE        81

BOOL scheduled;
int hybrid,hybrid_b,pmp;

int PARAM;
char *macro[LAST_ONE]; /* macro text */ 

char *functions[]={"MULTIPLY","MULTUP","SQUARE","REDC","ADDITION","INCREMENT",
                 "SUBTRACTION","DECREMENT","SUMMATION","INCREMENTATION",
                 "DECREMENTATION","MULTIPLY2","ADDITION2","SUBTRACTION2","PMULT",NULL};

char *names[]={"MUL_START","STEP","STEP1M","STEP1A","STEP2M",
               "STEP2A","MFIN","MUL_END","LAST","SQR_START","DSTEP",
               "DSTEP1M","DSTEP1A","DSTEP2M","DSTEP2A","SELF",
               "SFIN","SQR_END","REDC_START","RFINU","RFIND",
               "REDC_END","ADD_START","ADD","ADD_END","SUB_START","SUB",
               "SUB_END","INC_START","INC","INC_END","DEC_START","DEC",
               "DEC_END","KADD_START","KASL","KADD_END","KINC_START","KIDL",
               "KINC_END","KDEC_START","KDEC_END","STEPB","STEPB1M","STEPB1A","STEPB2M","STEPB2A",
               "H2_MUL_START","H2_STEP","H2_MFIN","H2_MUL_END",
               "H2_SQR_START","H2_DSTEP","H2_SELF","H2_SFIN","H2_SQR_END",
               "H4_MUL_START","H4_STEP","H4_MFIN","H4_MUL_END",
               "H4_SQR_START","H4_DSTEP","H4_SELF","H4_SFIN","H4_SQR_END","H2_LAST","H4_LAST",
                "PMUL_START","PMUL","PMUL_END","MULB_START","MULB_END","MBFIN",
                "H2_MULB_START","H2_MULB_END","H2_MBFIN","H2_STEPB",
                "H4_MULB_START","H4_MULB_END","H4_MBFIN","H4_STEPB",NULL};

BOOL white(char c)
{
    if (c==' ' || c=='\n' || c=='\r' || c=='\t') return TRUE;
    else return FALSE;
}

int skip(char *c,int i)
{
    while (white(c[i])) i++;
    return i;
}

int which(char *name,char *names[])
{
    int ipt=0;  
    while (names[ipt]!=NULL)
    {
        if (strcmp(name,names[ipt])==0) return ipt;
        ipt++;
    }
    return -1;
}

void m_prologue(FILE *dotc,int k,int m)
{
    fprintf(dotc,macro[STEP1M],k,m); 
}

void m_epilogue(FILE *dotc,int x)
{
    if (x==1) fprintf(dotc,macro[STEP1A]);
    else      fprintf(dotc,macro[STEP2A]);
}

void m_schedule(FILE *dotc,int x,int k,int m)
{
    if (x==1)
    {
        fprintf(dotc,macro[STEP2M],k,m);
        fprintf(dotc,macro[STEP1A]);
    }
    else
    {
        fprintf(dotc,macro[STEP1M],k,m);
        fprintf(dotc,macro[STEP2A]);
    }
}

void m_prologue2(FILE *dotc,int k,int m)
{
    fprintf(dotc,macro[STEPB1M],k,m); 
}

void m_epilogue2(FILE *dotc,int x)
{
    if (x==1) fprintf(dotc,macro[STEPB1A]);
    else      fprintf(dotc,macro[STEPB2A]);
}

void m_schedule2(FILE *dotc,int x,int k,int m)
{
    if (x==1)
    {
        fprintf(dotc,macro[STEPB2M],k,m);
        fprintf(dotc,macro[STEPB1A]);
    }
    else
    {
        fprintf(dotc,macro[STEPB1M],k,m);
        fprintf(dotc,macro[STEPB2A]);
    }
}

void s_prologue(FILE *dotc,int k,int m)
{
    fprintf(dotc,macro[DSTEP1M],k,m);
}

void s_epilogue(FILE *dotc,int x)
{
    if (x==1) fprintf(dotc,macro[DSTEP1A]);
    else      fprintf(dotc,macro[DSTEP2A]);
}

void s_schedule(FILE *dotc,int x,int k,int m)
{
    if (x==1)
    {
        fprintf(dotc,macro[DSTEP2M],k,m);
        fprintf(dotc,macro[DSTEP1A]);
    }
    else
    {
        fprintf(dotc,macro[DSTEP1M],k,m);
        fprintf(dotc,macro[DSTEP2A]);
    }
}

/* Insert functions into template file */

void insert(int index,FILE *dotc)
{
    int i,j,k,m,n,x,inc;
    switch (index)
    {
    case PMULT:
        if (!pmp) break;
        fprintf(dotc,macro[PMUL_START]);
        for (i=0;i<PARAM;i++)
        {
            fprintf(dotc,macro[PMUL],i,i,i);
        }
        fprintf(dotc,macro[PMUL_END]);
        break;
    case MULTIPLY2:
        inc=1;
        if (hybrid_b)
        {
            inc=hybrid_b;
            if (hybrid_b==2)  fprintf(dotc,macro[H2_MULB_START]);
            if (hybrid_b==4)  fprintf(dotc,macro[H4_MULB_START]);
        }
        else fprintf(dotc,macro[MULB_START]);
        for (i=n=0;i<PARAM;i+=inc,n+=inc)
        {    
            k=0; m=i;
            if (scheduled)
            {
                x=1;
                m_prologue2(dotc,k,m);
                k++; m--;

                while (k<=i)
                {
                    m_schedule2(dotc,x,k,m);
                    k++; m--;
                    x=3-x;
                }

                m_epilogue2(dotc,x);

            }
            else
            {
                while (k<=i)
                {
                    if (hybrid_b)
                    {
                        if (hybrid_b==2) fprintf(dotc,macro[H2_STEPB],k,k,m,m);
                        if (hybrid_b==4) fprintf(dotc,macro[H4_STEPB],k,k,k,k,m,m,m,m);
                    }
                    else fprintf(dotc,macro[STEPB],k,m);
                    k+=inc; m-=inc;
                }

            }
            if (hybrid_b) 
            {
                if (hybrid_b==2) fprintf(dotc,macro[H2_MBFIN],n,n+1);
                if (hybrid_b==4) fprintf(dotc,macro[H4_MBFIN],n,n+1,n+2,n+3);
            }
            else fprintf(dotc,macro[MBFIN],n);

        }
        for (i=0;i<PARAM-inc;i+=inc,n+=inc)
        {
            k=i+inc; m=PARAM-inc;
            if (scheduled)
            {
                x=1;
                m_prologue2(dotc,k,m);
                k++; m--;

                while (k<=PARAM-1)
                {
                    m_schedule2(dotc,x,k,m);
                    k++; m--;
                    x=3-x;
                }
                m_epilogue2(dotc,x);
            }
            else
            {
                while (k<=PARAM-inc)
                {
                    if (hybrid_b)
                    {
                        if (hybrid_b==2) fprintf(dotc,macro[H2_STEPB],k,k,m,m);
                        if (hybrid_b==4) fprintf(dotc,macro[H4_STEPB],k,k,k,k,m,m,m,m);
                    }
                    else fprintf(dotc,macro[STEPB],k,m);
                    k+=inc; m-=inc;
                }
            }
            if (hybrid_b) 
            {
                if (hybrid_b==2) fprintf(dotc,macro[H2_MBFIN],n,n+1);
                if (hybrid_b==4) fprintf(dotc,macro[H4_MBFIN],n,n+1,n+2,n+3);
            }
            else fprintf(dotc,macro[MBFIN],n);
    
        }

        if (hybrid_b) 
        {
            if (hybrid_b==2) fprintf(dotc,macro[H2_MULB_END],2*PARAM-2);
            if (hybrid_b==4) fprintf(dotc,macro[H4_MULB_END],2*PARAM-4,2*PARAM-3,2*PARAM-2);
        }
        else fprintf(dotc,macro[MULB_END]);
    break;
    case MULTIPLY: 
        inc=1;
        if (hybrid)
        {
            inc=hybrid;
            if (hybrid==2)  fprintf(dotc,macro[H2_MUL_START]);
            if (hybrid==4)  fprintf(dotc,macro[H4_MUL_START]);
        }
        else fprintf(dotc,macro[MUL_START]);
        for (i=n=0;i<PARAM;i+=inc,n+=inc)
        {    
            k=0; m=i;

            if (scheduled)
            {
                x=1;
                m_prologue(dotc,k,m);
                k++; m--;

                while (k<=i)
                {
                    m_schedule(dotc,x,k,m);
                    k++; m--;
                    x=3-x;
                }

                m_epilogue(dotc,x);

            }
            else
            {
                while (k<=i)
                {
                    if (hybrid)
                    {
                        if (hybrid==2) fprintf(dotc,macro[H2_STEP],k,k,m,m);
                        if (hybrid==4) fprintf(dotc,macro[H4_STEP],k,k,k,k,m,m,m,m);
                    }
                    else fprintf(dotc,macro[STEP],k,m);
                    k+=inc; m-=inc;
                }
            }
            if (hybrid) 
            {
                if (hybrid==2) fprintf(dotc,macro[H2_MFIN],n,n+1);
                if (hybrid==4) fprintf(dotc,macro[H4_MFIN],n,n+1,n+2,n+3);
            }
            else fprintf(dotc,macro[MFIN],n);
        }
        for (i=0;i<PARAM-inc;i+=inc,n+=inc)
        {
            k=i+inc; m=PARAM-inc;

            if (scheduled)
            {
                x=1;
                m_prologue(dotc,k,m);
                k++; m--;

                while (k<=PARAM-1)
                {
                    m_schedule(dotc,x,k,m);
                    k++; m--;
                    x=3-x;
                }
                m_epilogue(dotc,x);
            }
            else
            {
                while (k<=PARAM-inc)
                {
                    if (hybrid)
                    {
                        if (hybrid==2) fprintf(dotc,macro[H2_STEP],k,k,m,m);
                        if (hybrid==4) fprintf(dotc,macro[H4_STEP],k,k,k,k,m,m,m,m);
                    }
                    else fprintf(dotc,macro[STEP],k,m);
                    k+=inc; m-=inc;
                }
            }
            if (hybrid) 
            {
                if (hybrid==2) fprintf(dotc,macro[H2_MFIN],n,n+1);
                if (hybrid==4) fprintf(dotc,macro[H4_MFIN],n,n+1,n+2,n+3);
            }
            else fprintf(dotc,macro[MFIN],n);
        }
        if (hybrid) 
        {
            if (hybrid==2) fprintf(dotc,macro[H2_MUL_END],2*PARAM-2,2*PARAM-1);
            if (hybrid==4) fprintf(dotc,macro[H4_MUL_END],2*PARAM-4,2*PARAM-3,2*PARAM-2,2*PARAM-1);
        }
        else fprintf(dotc,macro[MUL_END],2*PARAM-1);
        break;
    case MULTUP:
        inc=1;
        if (hybrid)
        {
            inc=hybrid;
            if (hybrid==2)  fprintf(dotc,macro[H2_MUL_START]);
            if (hybrid==4)  fprintf(dotc,macro[H4_MUL_START]);
        }
        else fprintf(dotc,macro[MUL_START]);

        for (i=n=0;i<PARAM-inc;i+=inc,n+=inc)
        {    
            k=0; m=i;

            if (scheduled)
            {   
                x=1;
                m_prologue(dotc,k,m);
                k++; m--;

                while (k<=i)
                {
                    m_schedule(dotc,x,k,m);
                    k++; m--;
                    x=3-x;
                }
                m_epilogue(dotc,x);
            }
            else
            {
                while (k<=i)
                {
                    if (hybrid)
                    {
                        if (hybrid==2) fprintf(dotc,macro[H2_STEP],k,k,m,m);
                        if (hybrid==4) fprintf(dotc,macro[H4_STEP],k,k,k,k,m,m,m,m);
                    }
                    else fprintf(dotc,macro[STEP],k,m);
                    k+=inc; m-=inc;
                }
            }
            if (hybrid) 
            {
                if (hybrid==2) fprintf(dotc,macro[H2_MFIN],n,n+1);
                if (hybrid==4) fprintf(dotc,macro[H4_MFIN],n,n+1,n+2,n+3);
            }
            else fprintf(dotc,macro[MFIN],n);
        }
        k=0; m=PARAM-inc;
        while (k<=i)
        {
            if (hybrid)
            {
                if (hybrid==2) fprintf(dotc,macro[H2_LAST],k,k,m,m);
                if (hybrid==4) fprintf(dotc,macro[H4_LAST],k,k,k,k,m,m,m,m);
            }
            else fprintf(dotc,macro[LAST],k,m);
            k+=inc; m-=inc;
        }

        if (hybrid) 
        {
            if (hybrid==2) fprintf(dotc,macro[H2_MUL_END],PARAM-2,PARAM-1);
            if (hybrid==4) fprintf(dotc,macro[H4_MUL_END],PARAM-4,PARAM-3,PARAM-2,PARAM-1);
        }
        else fprintf(dotc,macro[MUL_END],PARAM-1);
        break;
    case SQUARE:   
        inc=1;
        if (hybrid)
        {
            inc=hybrid;
            if (hybrid==2) fprintf(dotc,macro[H2_SQR_START]);
            if (hybrid==4) fprintf(dotc,macro[H4_SQR_START]);
        }
        else fprintf(dotc,macro[SQR_START]);
        for (i=n=0;i<PARAM;i+=inc,n+=inc)
        {
            k=0; m=i;

            if (scheduled)
            {  
                if (k<m)
                {
                    x=1;
                    s_prologue(dotc,k,m);
                    k++; m--;

                    while (k<m)
                    {
                        s_schedule(dotc,x,k,m);
                        k++; m--;
                        x=3-x;
                    }
                   s_epilogue(dotc,x);
                }
            }
            else
            {
                while (k<m)
                {
                    if (hybrid) 
                    {
                        if (hybrid==2) fprintf(dotc,macro[H2_DSTEP],k,k,m,m);
                        if (hybrid==4) fprintf(dotc,macro[H4_DSTEP],k,k,k,k,m,m,m,m);
                    }
                    else fprintf(dotc,macro[DSTEP],k,m);
                    k+=inc; m-=inc;
                }
            }
            if (hybrid)
            {
                if (hybrid==2 && n%4==0) fprintf(dotc,macro[H2_SELF],n/2,n/2);
                if (hybrid==4 && n%8==0) fprintf(dotc,macro[H4_SELF],n/2,n/2,n/2,n/2);
            }
            else
            {
                if (n%2==0) fprintf(dotc,macro[SELF],n/2,n/2);
            } 
            if (hybrid) 
            {
                if (hybrid==2) fprintf(dotc,macro[H2_SFIN],n,n+1);
                if (hybrid==4) fprintf(dotc,macro[H4_SFIN],n,n+1,n+2,n+3);
            }
            else fprintf(dotc,macro[SFIN],n);
        }
        for (i=0;i<PARAM-inc;i+=inc,n+=inc)
        {
            k=i+inc; m=PARAM-inc;

            if (scheduled)
            {
                if (k<m)
                {
                    x=1;
                    s_prologue(dotc,k,m);
                    k++; m--;

                    while (k<m)
                    {
                        s_schedule(dotc,x,k,m);
                        k++; m--;
                        x=3-x;
                    }
                    s_epilogue(dotc,x);
                }
            }
            else
            {
                while (k<m)
                {
                    if (hybrid) 
                    {
                        if (hybrid==2) fprintf(dotc,macro[H2_DSTEP],k,k,m,m);
                        if (hybrid==4) fprintf(dotc,macro[H4_DSTEP],k,k,k,k,m,m,m,m);
                    }
                    else fprintf(dotc,macro[DSTEP],k,m);
                    k+=inc; m-=inc;
                }
            }
            if (hybrid)
            {
                if (hybrid==2 && n%4==0) fprintf(dotc,macro[H2_SELF],n/2,n/2);
                if (hybrid==4 && n%8==0) fprintf(dotc,macro[H4_SELF],n/2,n/2,n/2,n/2);
            }
            else
            {
                if (n%2==0) fprintf(dotc,macro[SELF],n/2,n/2);
            }
            if (hybrid) 
            {
                if (hybrid==2) fprintf(dotc,macro[H2_SFIN],n,n+1);
                if (hybrid==4) fprintf(dotc,macro[H4_SFIN],n,n+1,n+2,n+3);
            }
            else fprintf(dotc,macro[SFIN],n);
        }
        if (hybrid) 
        {
            if (hybrid==2) fprintf(dotc,macro[H2_SQR_END],2*PARAM-2,2*PARAM-1);
            if (hybrid==4) fprintf(dotc,macro[H4_SQR_END],2*PARAM-4,2*PARAM-3,2*PARAM-2,2*PARAM-1);
        }
        else fprintf(dotc,macro[SQR_END],2*PARAM-1);
        break;
    case REDC:  
        fprintf(dotc,macro[REDC_START]);
        fprintf(dotc,macro[RFINU],0,0);

        for (i=n=1;i<PARAM;i++,n++)
        {
            k=0; m=i;

            if (scheduled)
            {
                x=1;
                m_prologue(dotc,k,m);
                k++; m--;

                while (k<i)
                {
                    m_schedule(dotc,x,k,m);
                    k++; m--;
                    x=3-x;
                }
                m_epilogue(dotc,x);
            }
            else
            {
                while (k<i)
                    fprintf(dotc,macro[STEP],k++,m--);
            }
            fprintf(dotc,macro[RFINU],n,n);
        }
        for (i=0;i<PARAM-1;i++,n++)
        {
            k=i+1; m=PARAM-1;

            if (scheduled)
            {
                x=1;
                m_prologue(dotc,k,m);
                k++; m--;

                while (k<=PARAM-1)
                {
                    m_schedule(dotc,x,k,m);
                    k++; m--;
                    x=3-x;
                }
                m_epilogue(dotc,x);
            }
            else
            {
                while (k<=PARAM-1)
                    fprintf(dotc,macro[STEP],k++,m--);
            }
            fprintf(dotc,macro[RFIND],n,n);
        }
        fprintf(dotc,macro[REDC_END],2*PARAM-1,2*PARAM-1);
        break;
    case ADDITION:    
        fprintf(dotc,macro[ADD_START]);
        for (i=1;i<PARAM;i++)
            fprintf(dotc,macro[ADD],i,i,i);
        fprintf(dotc,macro[ADD_END]);
        break;
    case ADDITION2:
        fprintf(dotc,macro[ADD_START]);
        for (i=1;i<2*PARAM;i++)
            fprintf(dotc,macro[ADD],i,i,i);
        fprintf(dotc,macro[ADD_END]);
        break;
    case INCREMENT:
        fprintf(dotc,macro[INC_START]);
        for (i=1;i<PARAM;i++)
            fprintf(dotc,macro[INC],i,i,i);
        fprintf(dotc,macro[INC_END]);
        break;
    case SUBTRACTION:
        fprintf(dotc,macro[SUB_START]);
        for (i=1;i<PARAM;i++)
            fprintf(dotc,macro[SUB],i,i,i);
        fprintf(dotc,macro[SUB_END]);
        break;
    case SUBTRACTION2:
        fprintf(dotc,macro[SUB_START]);
        for (i=1;i<2*PARAM;i++)
            fprintf(dotc,macro[SUB],i,i,i);
        fprintf(dotc,macro[SUB_END]);
        break;
    case DECREMENT:
        fprintf(dotc,macro[DEC_START]);
        for (i=1;i<PARAM;i++)
            fprintf(dotc,macro[DEC],i,i,i);
        fprintf(dotc,macro[DEC_END]);
        break;
    case SUMMATION:
        fprintf(dotc,macro[KADD_START],1);
        for (i=0;i<PARAM;i++)
            fprintf(dotc,macro[ADD],i,i,i);
        fprintf(dotc,macro[KASL],2,PARAM,PARAM,PARAM,1,2);
        fprintf(dotc,macro[KADD_END]);
        break;
    case INCREMENTATION:
        fprintf(dotc,macro[KINC_START],3);
        for (i=0;i<PARAM;i++)
            fprintf(dotc,macro[INC],i,i,i);
        fprintf(dotc,macro[KIDL],4,PARAM,PARAM,3,4);
        fprintf(dotc,macro[KINC_END]);
        break;
    case DECREMENTATION:
        fprintf(dotc,macro[KDEC_START],5);
        for (i=0;i<PARAM;i++)
            fprintf(dotc,macro[DEC],i,i,i);
        fprintf(dotc,macro[KIDL],6,PARAM,PARAM,5,6);
        fprintf(dotc,macro[KDEC_END]);
        break;
    default:
        break;
    }
}

int main(int argc,char **argv)
{
    FILE *template,*macros,*dotc;
    int i,ip,ptr,index,size;
    BOOL open,error;
    char fname[80],tmpl[80],name[20];
    char line[133];
    argc--; argv++;
    if (argc<3 || argc>4)
    {
       printf("Bad arguments\n");
       printf("mex <parameter> <.mcs file> <.tpl file>\n");
       printf("Use flag -s for scheduled code\n");
       printf("Examples:\n");
       printf("mex 6 ms86 mrcomba\n");
       printf("mex -s 8 c mrkcm\n");
       exit(0);
    }
    ip=0;
    scheduled=FALSE;
    if (strcmp(argv[0],"-s")==0)
    {
        ip=1;
        scheduled=TRUE;
    }

    PARAM=atoi(argv[ip]);
    if (PARAM<2 || PARAM>40)
    {
        printf("Invalid parameter\n");
        exit(0);
    }
    strcpy(fname,argv[ip+1]);
    strcat(fname,".mcs");
    macros=fopen(fname,"rt");
    if (macros==NULL)
    {
        printf("Macro file %s not found\n",fname);
        exit(0);
    }

    strcpy(tmpl,argv[ip+2]);
    strcat(tmpl,".tpl");
    template=fopen(tmpl,"rt");
    if (template==NULL)
    {
        printf("Template file %s file not found\n",tmpl);
        exit(0);
    }
    strcpy(tmpl,argv[ip+2]);
    strcat(tmpl,".c");
    dotc=fopen(tmpl,"wt");
    if (dotc==NULL)
    {
        printf("Unable to open %s for output\n",tmpl);
        exit(0);
    }

    for (i=0;i<LAST_ONE;i++) macro[i]=NULL;

/* read in the macros - first pass to determine size and check for errors */
    open=error=FALSE;
    while (1)
    {
        if (fgets(line,132,macros)==NULL) break;
        if (line[0]==';') continue;
        
        if (!open && strncmp(line,"MACRO",5)==0) 
        {
                open=TRUE;
                ptr=6; i=0;
                ptr=skip(line,ptr);
                while (!white(line[ptr])) name[i++]=line[ptr++];
                name[i]='\0';
                index=which(name,names);
                if (index<0)
                {
                    error=TRUE;
                    break;
                }
                size=0;
                continue;
        }
        if (open && strncmp(line,"ENDM",4)==0) 
        {
                open=FALSE;
                macro[index]=(char *)malloc(size+1);
                macro[index][0]='\0';
        }

        if (open) size+=strlen(line);
    }
    fclose(macros);
    if (error)
    {
        printf("no such macro - %s\n",name);
        exit(0);
    }

/* read in the macros - second pass to store macros */     
    macros=fopen(fname,"rt");   
    while (1)
    {
        if (fgets(line,132,macros)==NULL) break;
        if (line[0]==';') continue;

        if (!open && strncmp(line,"MACRO",5)==0) 
        {
                open=TRUE;
                ptr=6; i=0;
                ptr=skip(line,ptr);
                while (!white(line[ptr])) name[i++]=line[ptr++];
                name[i]='\0';
                index=which(name,names);
                continue;
        }
        if (open && strncmp(line,"ENDM",4)==0) open=FALSE;

        if (open) strcat(macro[index],line);
    }
    fclose(macros);

    if (macro[PMUL]==NULL)
    {
        printf("Pseudo Mersenne Primes not (yet) supported for this architecture in file %s\n",fname);
        pmp=0;
    }
    else pmp=1;

    if (scheduled && macro[STEP1M]==NULL)
    {
        printf("Error - scheduling not supported in file %s\n",fname);
        exit(0);
    }
    hybrid=0;
    if (macro[H2_STEP]!=NULL) hybrid=2; 
    if (macro[H4_STEP]!=NULL) hybrid=4;

    hybrid_b=0;
    if (macro[H2_STEPB]!=NULL) hybrid_b=2; 
    if (macro[H4_STEPB]!=NULL) hybrid_b=4;

    if (hybrid)
    {
        printf("Found hybrid macros - max step size = %d\n",hybrid);
        if (PARAM%hybrid!=0)
        {
            printf("Warning - %d should be a multiple of %d for hybrid method\n",PARAM,hybrid);
            hybrid=0;
        }
    }
    
    if (hybrid_b)
    {
        printf("Found hybrid macros for binary case - max step size = %d\n",hybrid_b);
        if (PARAM%hybrid_b!=0)
        {
            printf("Warning - %d should be a multiple of %d for hybrid method\n",PARAM,hybrid_b);
            hybrid_b=0;
        }
    }

    if ((scheduled && hybrid) || (scheduled && hybrid_b))
    {
        printf("Error - scheduling not supported in file %s\n",fname);
        exit(0);
    }

/* Insert macros into dotc file */
    
    while (1)
    {
        if (fgets(line,132,template)==NULL) break;
        fputs(line,dotc);
        if (strncmp(line,"/***",4)==0)
        {
                ptr=4; i=0;
                ptr=skip(line,ptr);
                while (!white(line[ptr])) name[i++]=line[ptr++];
                name[i]='\0';

                index=which(name,functions);
             /*   printf("Recognize %s index %d\n",name,index);    */
                if (index<0)
                {
                    error=TRUE;
                    break;
                }
                insert(index,dotc);
        }
    }
    
    if (error)
        printf("no such function - %s\n",name);
   
    fclose(template);
    fclose(dotc);
    return 0;
}

