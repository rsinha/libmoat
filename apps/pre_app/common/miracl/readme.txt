IMPORTANT! See UPDATE.DOC for latest changes

The distribution media contains the following files

  README.TXT      -    This file
  FIRST.TXT       -    Read this next
  MSVISUAL.TXT    -    Microsoft Visual C++ V6.0 quick-start instructions
  VC2005.TXT      -    Microsoft Visual C++ V8.0 quick-start instructions
  BORLAND.TXT     -    Borland C quick-start instructions
  ARM.TXT         -    ARM processor advice
  SPARC.TXT       -    SPARC processor advise
  ITANIUM.TXT     -    ITANIUM processor advise
  AMD64.TXT       -    AMD64 processor advise
  SSE2.TXT        -    SSE2 extensions advise
  POWERPC.TXT     -    POWERPC processor advice
  LINUX.TXT       -    Some advice for Linux users 
  MANUAL.DOC      -    The Manual - read it!
  PROBLEMS.TXT    -    Known problems with MIRACL
  UPDATE.TXT      -    MIRACL Update History
  KCMCOMBA.TXT    -    Using super-fast techniques
  MAKEMCS.TXT     -    How to create your own .mcs file
  DOUBLE.TXT      -    Using a double underlying type
  FLOAT.TXT       -    Multiprecision floating-point
  CONFIG.C        -    Program to automatically generate a mirdef.h file 
  MEX.C           -    Program to insert fast macros into mrcomba.c/mrkcm.c 

In the subdirectory SOURCE

  MRMULDV.ANY  -    Contains assembly language versions of muldiv,muldvm,
                    muldvd and muldvd2
  MRMULDV.S    -    Version of the above for Linux i386 GCC
  MRMULDV.S64  -    Version of the above for Linux x86_64 GCC
  MRMULDV.C    -    Version of the above for Win32
  MRMULDV.CCC  -    Standard C version
  MRMULDV.GPP  -    Version of the above for DJGPP GCC
  MR*.C        -    MIRACL library source files
  MRCOMBA.TPL  -    Template file for fast Comba method
  MRKCM.TPL    -    Template file for fast KCM method
  C.MCS        -    C macros for use with above
  C1.MCS       -    Alternate C macros
  MS86.MCS     -    Microsoft/Borland 80*86/Pentium macros for use with above
  GCC386.MCS   -    GCC compiler compatible Pentium macros
  ARM.MCS      -    ARM processor macros
  GCCARM.MCS   -    GCC compatable version of the above
  AVR.MCS      -    Atmel Atmega128 processor macros
  MSP430.MCS   -    TI msp430 support (uses hardware multiplier)
  GCCMSP430.MCS -   GCC compatable version of the above
  SPARC32.MCS  -    32-bit Sparc processor macros
  SPARC64.MCS  -    64-bit Sparc processor macros
  ITANIUM.MCS  -    64-bit Itanium processor macros
  AMD64.MCS    -    64-bit AMD64 procesor macros
  SSE2.MCS     -    Pentium 4 SSE2 instructions for Microsoft compiler
  GCCPPC.MCS   -    PowerPC processor macros
  GCCSSE2.MCS  -    Pentium 4 SSE2 instructions for GCC compiler
  BMARK.C      -    Benchmark program for Public Key methods
  IMRATIO.C    -    Benchmark program. Calculates S/M, I/M and J/M ratios over GF(p)
  IMRATIO2.C   -    Benchmark program. Calculates S/M and I/M ratios over GF(2^m)
  MERSENNE.C   -    Mersenne primes
  FACT.C       -    Factorials
  BRUTE.C      -    Brute-force factorisation
  BRENT.C      -    Brent-pollard factoring
  BRENT_MT.C   -    Example of generic Multi-Threading
  HAIL.C       -    Hailstone numbers
  PALIN.C      -    Palindromic numbers
  GENKEY.C     -    Generate Public and Private keys
  ENCODE.C     -    Encode using RSA method
  DECODE.C     -    Decode using RSA method
  ENCIPH.C     -    Encipher using Probabalistic method
  DECIPH.C     -    Decipher using Probabalistic method
  PK-DEMO.C    -    Demo of RSA/El Gamal/Diffie-Hellman/Elliptic Curve... 
  IDENTITY.C   -    ID based key exchange program
  HILBERT.C    -    Solve special system of equations
  SAMPLE.C     -    Example of Flash arithmetic
  ROOTS.C      -    Square roots
  POLLARD.C    -    Pollard's factoring method
  WILLIAMS.C   -    William's factoring method
  LENSTRA.C    -    Lenstra's factoring method
  QSIEVE.C     -    The Quadratic Sieve
  RATCALC.C    -    Rational Scientific Calculator
  FACTOR.C     -    Factoring Program source
  KANGAROO.C   -    Pollards Lambda method for discrete logs
  INDEX.C      -    Pollards rho method for discrete logs
  GENPRIME.C   -    Generates prime for above
  LIMLEE.C     -    Lim-Lee prime generation
  DSSETUP.C    -    Digital Signature Standard setup program
  DSSGEN.C     -    Digital Signature Standard key generator program
  DSSIGN.C     -    Digital Signature Standard signature program
  DSSVER.C     -    Digital Signature Standard verification program
  ECDH2M.C     -    Example EC Diffie-Hellman program for constrained environments (static stack-only)
  ECDH2M16.C   -    16-bit version of the above
  ECDH2M8.c    -    8-bit version of the above
  ECDHP.C      -       ditto, over GF(p) - 32-bit
  ECDHP32.c    -       ditto, over GF(p) - Nice ARM example (32-bits)
  ECDHP8.C     -       ditto, over GF(p), 8-bit version
  ECDHP16.C    -       ditto, over GF(p), 16-bit version
  ECSGEN.C     -    DSS (Elliptic Curve GF(p) variation) key generator program
  ECSIGN.C     -    DSS (Elliptic Curve GF(p) variation) signature program
  ECSVER.C     -    DSS (Elliptic Curve GF(p) variation) verification program
  ECSGEN_S.C   -    DSS (Elliptic Curve GF(p) variation) key generator program (static stack-only version)
  ECSIGN_S.C   -    DSS (Elliptic Curve GF(p) variation) signature program (static stack-only version)
  ECSVER_S.C   -    DSS (Elliptic Curve GF(p) variation) verification program (static stack-only version)
  ECSGEN2.C    -    DSS (Elliptic Curve GF(2^m) variation) key generator program
  ECSIGN2.C    -    DSS (Elliptic Curve GF(2^m) variation) signature program
  ECSVER2.C    -    DSS (Elliptic Curve GF(2^m) variation) verification program
  ECSGEN2S.C   -    DSS (Elliptic Curve GF(2^m) variation) key generator program (static stack-only version)
  ECSIGN2S.C   -    DSS (Elliptic Curve GF(2^m) variation) signature program (static stack-only version)
  ECSVER2S.C   -    DSS (Elliptic Curve GF(2^m) variation) verification program (static stack-only version)
  BRICK.C      -    Brickell's method for fast exponentiation
  EBRICK.C     -    Same for GF(p) Elliptic Curves
  EBRICK2.C    -    Same for GF(2^m) Elliptic Curves
  BIG.CPP      -    Big function implementations
  ZZN.CPP      -    ZZn function implementations
  ECN.CPP      -    ECn function implementations
  EC2.CPP      -    EC2 function implementations
  GF2M.CPP     -    GF(2^m) function implementations
  CRT.CPP      -    Crt function implementations
  FLASH.CPP    -    Flash function implementations   
  FLOATING.CPP -    Float function implementations
  PAL_ENC.CPP  -    Paillier Homomorphic Encryption Program
  PAL_DEC.CPP  -    Paillier Homomorphic Decryption Program
  THREADWN.CPP -    Example of Windows Multi-threading
  THREADUX.CPP -    Example of Unix Multi-Threading
  THREADMP.CPP -    Example of openMP Multi-Threading
  FINDBASE.CPP -    Find irreducible polynomial for GF(2^m) programs
  IRP.CPP      -    Generates code to implement irreducible polynomial
  NEWBASIS.CPP -    Converts from one irreducible polynomial representation to another
  FACT.CPP     -    Example C++ source (uses BIG.H)
  HAIL.CPP     -            "                "
  PALIN.CPP    -            "                "
  BRUTE.CPP    -            "                "
  MERSENNE.CPP -            "                "
  QSIEVE.CPP   -            "                " 
  GENKEY.CPP   -            "                " 
  ENCODE.CPP   -            "                " 
  DECODE.CPP   -            "                "
  ENCIPH.CPP   -            "                " 
  DECIPH.CPP   -            "                "
  PK-DEMO.CPP  -            "                "
  LIMLEE.CPP   -            "                "
  DSSETUP.CPP  -            "                "
  DSSGEN.CPP   -            "                "
  DSSIGN.CPP   -            "                "
  DSSVER.CPP   -            "                "  
  KANGAROO.CPP -            "                "
  INDEX.CPP    -            "                "
  GENPRIME.CPP -            "                "
  BRICK.CPP    -            "                "
  EBRICK.CPP   -    Example C++ source (uses ECN.H)
  ECSGEN.CPP   -            "                "
  ECSIGN.CPP   -            "                "
  ECSVER.CPP   -            "                "  
  EBRICK2.CPP  -    Example C++ source (uses EC2.H)
  ECSGEN2.CPP  -            "                "
  ECSIGN2.CPP  -            "                "
  ECSVER2.CPP  -            "                "  
  POLLARD.CPP  -    Example C++ source (uses ZZN.H)
  WILLIAMS.CPP -            "                "  
  LENSTRA.CPP  -            "                "  
  BRENT.CPP    -            "                "
  SAMPLE.CPP   -    Example C++ source (uses FLASH.H)
  ROOTS.CPP    -            "                "
  HILBERT.CPP  -            "                "
  FSAMPLE.CPP  -    Example C++ source (uses FLOATING.H)
  CARDANO.CPP  -    Example C++ source (uses ZZn2.H)

  Note how readable the C++ versions of the example programs look.

  In the subdirectory SOURCE/CURVE

  CM.CPP       -  Complex Multiplication - creates elliptic curves
  VARIABLE.H   -  Dummy Variable class
  POLY.H       -  Polynomial Class definition, elements from ZZn
  POLY.CPP     -  Polynomial Arithmetic with ZZn coefficients
  POLY2.H      -  Polynomial Class definition, elements from GF(2^m)
  POLY2.CPP    -  Polynomial Arithmetic with GF(2^m) coefficients
  FLPOLY.H     -  Polynomial Class definition, float elements
  FLPOLY.CPP   -  Polynomial arithmetic with float coefficients
  COMPLEX.H    -  Complex Float class definition
  COMPLEX.CPP  -  Complex Float class arithmetic
  CM.TXT       -  How to build the CM application
  POLYMOD.H    -  Polynomials mod a Polynomial - Class Definition
  POLYMOD.CPP  -  ZZn Polynomial arithmetic wrt a Polynomial Modulus
  POLY2MOD.H   -  Polynomials mod a Polynomial - Class Definition
  POLY2MOD.CPP -  GF(2^m) Polynomial arithmetic wrt a Polynomial Modulus
  TRANS.CPP    -  A simple utility to convert elliptic curve to Weierstrass
  SCHOOF.CPP   -  Schoof's method for counting points on a GF(p) elliptic curve
  SCHOOF2.CPP  -  Schoof's method for counting points on a GF(2^m) elliptic curve
  SCHOOF.TXT   -  How to build the schoof Application
  SCHOOF2.TXT  -  How to build the schoof2 Application
  PS_BIG.H     -  Power series with Big coefficients - Class Definition
  PS_BIG.CPP   -  Power Series Arithmetic
  PS_ZZN.H     -  Power series with ZZN coefficients - Class Definition
  PS_ZZN.CPP   -  Power Series Arithmetic
  POLYXY.H     -  Bivariate Polynomials - Class Definition
  POLYXY.CPP   -  Bivariate Polynomilas - Implementation
  POLY2XY.H    -  Bivariate Polynomials - Class Definition
  POLY2XY.CPP  -  Bivariate Polynomilas - Implementation
  MUELLER.CPP  -  Program to generate Modular Polynomials
  PROCESS.CPP  -  Program to process Modular Polynomials wrt a prime modulus
  SEA.CPP      -  Schoof-Elkies-Atkin-Mueller algorithm
  SEA.TXT      -  How to build the MUELLER/PROCESS/SEA applications
  WEIL.CPP     -  Calculates number of points on curve over extension field

  In the subdirectory SOURCE\P1363

  P1363.H      - P1363 Header File
  P1363.C      - P1363 implementation file
  TEST1363.c   - test driver for P1363 implementation
  RSA.C        - quick start RSA application

  In the subdirectory SOURCE\IBE

  IBE.TXT      - Read this first
  IBE_SET.CPP  - Create IBE paramters, and master key
  IBE_EXT.CPP  - Extract a private key from the Identity
  IBE_ENC.CPP  - Encrypt a file using identity
  IBE_DEC.CPP  - Decrypt a file using the private key
  IBE_DECP.CPP - Decrypt using precomputation
  IBE_DECB.CPP - Decrypt using batching
  IBE_ENCP.CPP - Demonstrate Encryption using precomputation
  BLS_GEN.CPP  - Boneh-Lynn-Shacham Short Signature key generation
  BLS_SIGN.CPP - Boneh-Lynn-Shacham signature
  BLS_VER.CPP  - Boneh-Lynn-Shacham signature verification
  ECN2.H       - Elliptic curves over Fp2 - Header file
  ECN2.CPP     - Elliptic curves over Fp2 - Implementation file
  ECN4.H       - Elliptic curves over Fp4 - Header file
  ECN4.CPP     - Elliptic curves over Fp4 - Implementation file
  ZZN2.H       - Fp2 arithmetic - Header file
  ZZN2.CPP     - Fp2 arithmetic - Implementation file
  ZZN3.H       - Fp3 arithmetic - Header file
  ZZN3.CPP     - Fp3 arithmetic - Implementation file
  ZZN4.H       - Fp4 arithmetic - Header file
  ZZN4.CPP     - Fp4 arithmetic - Implementation file
  ZZN8.H       - Fp8 arithmetic - Header file
  ZZN8.CPP     - Fp8 arithmetic - Implementation file
  ECN3.H/.CPP  - Elliptic curves over Fp3
  ZZN6.H/.CPP  - Fp6 arithmetic - 2 over 3
  ZZN6a.H/.CPP - Fp6 arithmetic - 3 over 2
  ZZN12.H/.CPP - Fp12 arithmetic - 2 over 3 over 2
  MNT.CPP      - Program to generate MNT elliptic curves
  MNT.ECS      - Non-supersingular curve, k=6, created by CM from MNT output
  FREEMAN.CPP  - Program to generate k=10 Freeman curves
  FOLKLORE.CPP - program to create pairing-friendly non-SS curves
  IRRED.CPP    - Finds irreducible polynomial - Experimental!
  AKE.TXT      - Some explanation for these programs. 
  AKE6.CPP     - Authenticated Key Exchange, k=6  - Experimental!
  AKE6T.CPP    - Authenticated Key Exchange, k=6, Ate pairing, sextic twist!
  BN.CPP       - Program to generate BN curves
  AKE12.CPP    - Authenticated Key Exchange, k=12, BN curve  - Experimental!
  AKE12T.CPP   - Authenticated Key Exchange, k=12, BN curve, Ate pairing, sextic twist!
  AKE2.CPP     - Same as above, but ZZn2 based
  AKE2SS.CPP   - Same as above, but uses a supersingular curve
  AKE4.CPP     - Same as above, but ZZn4 based
  AKEW4.CPP    - Variation on the above
  AKE8.CPP     - Same as above, but ZZn8 based
  AKEW8.CPP    - Variation on the above
  K2.ECS       - Non-supersingular curve, k=2 
  K2SS.ECS     - Supersingular curve, k=2
  K4.ECS       - Non-supersingular curve, k=4 
  K8.ECS       - Non-supersingular curve, k=8 
  WENG.ECS     - Non-supersingular curve, k=8
  DL.CPP       - Duursma-Lee Char 2 pairings
  DL2.CPP      - Trucnated-loop Barreto-Galbraith-O'hEigearaigh-Scott faster char 2 pairings
  BANDW.CPP    - Brezing & Weng curves
  NSS3.CPP     - Faster k=2 key exchange program
  NEWWEIL.CPP  - Uses New Weil pairing
  PAIRINGS.TXT - Details of pairing-based resources

  In the subdirectory INCLUDE
  
  MIRDEF.H16   -    Standard hardware specific header file for 16-bit computer
  MIRDEF.H32   -    Header file for full 32-bit Computer
  MIRDEF.H     -    Same as above
  MIRDEF.HPC   -    Header file for pseudo-32 bit computer
  MIRDEF.HAF   -    Header file for 16 bit use of 32 bit computer
  MIRDEF.HIO   -    Integer-Only 32-bit header file
  MIRACL.H     -    Main MIRACL header
  BIG.H        -    C++ header for 'big' numbers
  FLASH.H      -    C++ header for 'flash' numbers
  FLOATING.H   -    C++ header for 'float' numbers
  ZZN.H        -    C++ header for 'big' numbers mod n
  CRT.H        -    C++ header for chinese remainder thereom
  ECN.H        -    C++ header for GF(p) Elliptic Curves
  EC2.H        -    C++ header for GF(2^m) Elliptic Curves 
  GF2M.H       -    C++ header for GF(2^m)
  BRICK.H      -    C++ header for Brickell's method
  EBRICK.H     -    C++ header for Brickell's method (Elliptic Curve GF(p) version)
  EBRICK2.H    -    C++ header for Brickell's method (Elliptic Curve GF(2^m) version)

  In the subdirectory LIB

  *DOIT.BAT    -    Batch files for constructing libraries and sample progs.
  MIRACL.MAK   -    John Kennedy's UNIX make file
  BC32.LIB     -    Borland C++ V5.5 32 bit flat memory model MIRACL library 
  MS32.LIB     -    Microsoft C 32 bit MIRACL library (for Win95/WinNT)
  MIRACL.A     -    DJGPP GNU C MIRACL Library

  If using 16-bit Borland C++ V5.5 then use BCLDOIT.BAT to build MIRACL.LIB 
  Then copy MIRDEF.H16 to MIRDEF.H, and you're in business. Use BCXDOIT.BAT to 
  build a library for use with MIRDEF.HPC, to provide pseudo 32-bit performance 
  from a 16-bit compiler. BC32.LIB is a true 32-bit flat model library for use 
  with MIRDEF.H32. It was compiled with the Borland 32 bit compiler BCC32. 
  Programs generated in this way require a DOS Extender program (e.g. Borland 
  Powerpack for DOS), or Win32, or a Windows '95/98/NT environment. 
  MS32.LIB is for use with the MicroSoft 32 bit compiler and MIRDEF.H32 
  (for use with Windows95/98 or WinNT).

  Older versions of these compilers may also work with these precompiled 
  libraries (try it and see). If using another compiler then you must execute 
  an appropriate xxDOIT.BAT file to create the MIRACL library. 

  If a pre-compiled library is not available:-

  (1) Determine which of mirdef.h32/mirdef.h16/mirdef.haf/mirdef.hpc is 
      suitable for you, and/or compile and run config.c to automatically 
      generate a suitable mirdef.h.

  (2) If for performance reasons a non-portable version is to be built,
      select suitable assembly language routines from mrmuldv.any, or
      write them yourself (send us a copy!). Even better - produce a
      ,mcs file for the processor and use either the KCM or Comba method.

  (3) Compile and link together the mr*.c components into an object library.
      Also assemble and link in the assemble language component from 
      mrmuldv.any (if needed).  

  In the subdirectory EXE some precompiled example programs

  FACT.EXE     -    Factorial program
  ROOTS.EXE    -    Roots program
  PK-DEMO.EXE  -    Public Key Demo program  (32-bit)
  ENCIPH.EXE   -    Enciphering program
  DECIPH.EXE   -    Deciphering program
  PUBLIC.KEY   -    Public key for use by enciphering program
  PRIVATE.KEY  -    Private key for use by deciphering program
  SECP160/192/224/256/521.ecs - Parameter files for some standard elliptic curves
  NIST163/233/283/571.ecs  -    Parameter files for standard curves
  KOB163/233/283 -  Parameter files for Koblitz curves

  In the sub-directory FREE some FREEWARE 32-bit IBM PC Command prompt 
  specific applications. CM.EXE is free as well, but omitted here for space
  reasons. 
  
  READ.TXT     -    Read this first
  RATCALC.EXE  -    Rational Calculator
  FACTOR.EXE   -    General purpose Factoring Program  (80386+ only)
                    For maximum speed this is compiled as a true 32-bit
                    and runs in a 32-bit DOS Window

  These files (ONLY!!) are FREEWARE, and may be freely copied 
  and distributed, unmodified. Copyright remains with Shamus Software. 

