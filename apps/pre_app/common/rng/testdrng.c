/*

Copyright (c) 2014, Intel Corporation
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

    * Redistributions of source code must retain the above copyright 
      notice, this list of conditions and the following disclaimer.  

    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived from
      this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "drng.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "hexdump.h"

void test_rdrand();
void test_rdseed();

int main (int argc, char *argv[]) 
{
	unsigned int drng_features;

	/* Determine DRNG support */

	drng_features= get_drng_support();
	if ( drng_features == DRNG_NO_SUPPORT ) {
		printf("This CPU does not support Intel(R) Data Protection with Secure Key\n");
		return 1;
	}

	if ( drng_features & DRNG_HAS_RDRAND ) {
		printf("This CPU supports the RDRAND instruction\n");
	} else {
		printf("This CPU does not support the RDRAND instruction\n");
	}

	if ( drng_features & DRNG_HAS_RDSEED ) {
		printf("This CPU supports the RDSEED instruction\n");
	} else {
		printf("This CPU does not support the RDSEED instruction\n");
	}

	if ( drng_features & DRNG_HAS_RDRAND ) {
		test_rdrand();
	}

	if ( drng_features & DRNG_HAS_RDSEED ) {
		test_rdseed();
	}
}

void test_rdrand()
{
	unsigned int i, n;
	uint16_t rand16;
	uint32_t rand32, rand32ar[16];
#ifdef __x86_64__
	uint64_t rand64;
#endif
	unsigned char data[1024] __attribute__ ((aligned (16)));
	unsigned char *dp;

	/* Our primitives, without retries */

	printf("RDRAND without retries\n");

	if ( ! rdrand16_step(&rand16) ) {
		fprintf(stderr, "rdrand16_step: random number not available\n");
	} else {
		printf("rand16= %u\n", rand16);
	}

	if ( ! rdrand32_step(&rand32) ) {
		fprintf(stderr, "rdrand32_step: random number not available\n");
	} else {
		/* The prototyping here is to keep the gcc from throwing 
		 * warnings on printf */
		printf("rand32= %lu\n", (unsigned long) rand32);
	}
#ifdef __x86_64__
	if ( ! rdrand64_step(&rand64) ) {
		fprintf(stderr, "rdrand64_step: random number not available\n");
	} else {
		printf("rand64= %llu\n", (unsigned long long) rand64);
	}
#endif

	/* Our primitives, with retries */

	printf("RDRAND with up to %d retries, each\n", RDRAND_RETRIES);

	if ( ! rdrand16_retry(RDRAND_RETRIES, &rand16) ) {
		fprintf(stderr, "rdrand16_retry: random number not available\n");
	} else {
		printf("rand16= %u\n", rand16);
	}

	if ( ! rdrand32_retry(RDRAND_RETRIES, &rand32) ) {
		fprintf(stderr, "rdrand32_retry: random number not available\n");
	} else {
		/* The prototyping here is to keep the gcc from throwing 
		 * warnings on printf */
		printf("rand32= %lu\n", (unsigned long) rand32);
	}
#ifdef __x86_64__
	if ( ! rdrand64_retry(RDRAND_RETRIES, &rand64) ) {
		fprintf(stderr, "rdrand64_retry: random number not available\n");
	} else {
		printf("rand64= %llu\n", (unsigned long long) rand64);
	}
#endif

	/* Fill an array of 16 uints (32-bit rands) */

	printf("Fill an array of 16 unsigned ints with random values\n");
	n= rdrand_get_n_uints(16, rand32ar);
	printf("Got %u rands:\n", n);
	for (i= 0; i< n; ++i) {
		printf("val[%u]= %u\n", i, rand32ar[i]);
	}

	/*
	 * Fill an odd-sized array with bytes (this tests the code in
	 * rdrand_get_bytes which deals with unaligned block boundaries)
	 */

	printf("Fill unaligned buffer with 112 random bytes\n");
	memset(data, 0, 1024);

	n= rdrand_get_bytes(112, &data[5]);
	printf("Got %u bytes:\n", n);

	hexdump(data, 128);

	/* Now do it with an aligned block */

	printf("Fill an aligned buffer with 128 random bytes\n");
	memset(data, 0, 1024);

	n= rdrand_get_bytes(128, data);
	printf("Got %u bytes:\n", n);

	hexdump(data, 128);
}

void test_rdseed()
{
	uint16_t seed16;
	uint32_t seed32;
#ifdef __x86_64__
	uint64_t seed64;
#endif

	printf("RDSEED without retries\n");

	if ( ! rdseed16_step(&seed16) ) {
		fprintf(stderr, "rdseed16_step: random seed not available\n");
	} else {
		printf("seed16= %u\n", seed16);
	}

	if ( ! rdseed32_step(&seed32) ) {
		fprintf(stderr, "rdseed32_step: random seed not available\n");
	} else {
		/* The prototyping here is to keep the gcc from throwing 
		 * warnings on printf */
		printf("seed32= %lu\n", (unsigned long) seed32);
	}
#ifdef __x86_64__
	if ( ! rdseed64_step(&seed64) ) {
		fprintf(stderr, "rdseed64_step: random seed not available\n");
	} else {
		printf("seed64= %llu\n", (unsigned long long) seed64);
	}
#endif
}

