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
#include <gcrypt.h>
#include <stdint.h>
#include <string.h>

#define MIN_GCRYPT_VERSION "1.0.0"

/*
 * Generates a 128-bit RDRAND value with full entropy from two 64-bit
 * RDRANDs (or four 32-bit RDRANDs, if in 32-bit mode).
 *
 * Even though the DRNG generates 128-bit samples, the RDRAND instruction
 * can return, at most, a 64-bit integer. This /theoretically/ limits the
 * entropy to 64-bits. Because RDRAND is the output of a PRNG, that
 * entropy is also additive when two samples are concatenated.
 *
 * This /theoretically/ means that concatenating two 64-bit RDRAND values
 * results in a number with only 65 bits of brute-force prediction 
 * resistance.
 *
 * Note that this is a theoretical argument. The practicality of such an
 * attack is another matter, since the DRNG in reality splits its samples
 * into two 64-bit values, but there are circumstances where designing
 * for theoretical limits and an ideal attacker is important in 
 * cryptography.
 *
 * DO YOU NEED THIS PROCEDURE?
 *
 * If you are generating STATIC, 128-bit encryption keys--namely 128-bit
 * keys that will be created once and not changed or will otherwise live 
 * on for a very long time--then you need either 1) RDSEED, or 2) this
 * procedure for RDRAND. If you don't have access to RDSEED, then THIS
 * PROCEDURE IS FOR YOU.
 *
 * If you are generating STATIC keys LARGER than 128 bits, then you need
 * either 1) RDSEED, or 2) the procedure to generate seeds from RDRAND.
 * THIS PROCEDURE IS NOT FOR YOU.
 *
 * Short-lived/ephemeral keys, nonces, IVs, session keys, etc. and 
 * virtually all other procedures that require high-quality random numbers
 * can simply concatenate RDRAND. Just call drng_get_bytes() or some
 * equivalent function. THIS PROCEDURE IS NOT FOR YOU.
 */

int main (int argc, char *argv[])
{
	gcry_md_hd_t gcry_hash_hd;
	gcry_error_t gcry_error;
	unsigned char rand[16];
	unsigned char *digest;

	/*
	 * Read in 16 bytes to our buffer. This is the equivalent of
	 * 2 x rand64 (or 4 x rand32 in 32-bit mode).
	 */

	if ( rdrand_get_bytes(16, (unsigned char *) rand) < 16 ) {
		fprintf(stderr, "Random values not available\n");
		return 1;
	}

	/*
	 * Use gcrypt for the HMAC_SHA256 hashing. This results in a 256-bit
	 * hash, but we only need 128 of those.
	 * 
	 * We can use a NULL key for this operation. SHA256 hashing is
	 * sufficient for our purposes, but HMAC_SHA256 is a better
	 * randomness extractor. We don't "lose" anything by using a 
	 * fixed key here, though if you are paranoid you can generate
	 * random keys using RDRAND.
	 */

	if (!gcry_check_version(MIN_GCRYPT_VERSION)) {
		fprintf(stderr,
			"gcry_check_version: have version %s, need version %s or newer",
			gcry_check_version(NULL), MIN_GCRYPT_VERSION
		);

		return 1;
	}

	gcry_error= gcry_md_open(&gcry_hash_hd, GCRY_MD_SHA256,
		GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC);
	if ( gcry_error ) {
		fprintf(stderr, "gcry_md_open: %s", gcry_strerror(gcry_error));
		return 1;
	}

	gcry_error= gcry_md_setkey(gcry_hash_hd, NULL, 0);
	if ( gcry_error ) { 
		fprintf(stderr, "gcry_md_setkey: %s", gcry_strerror(gcry_error));
		gcry_md_close(gcry_hash_hd);
		return 1;
	}

	gcry_md_write(gcry_hash_hd, rand, 16);

	digest= gcry_md_read(gcry_hash_hd, GCRY_MD_SHA256);
	if ( digest == NULL ) {
		fprintf(stderr, "gcry_md_read: could not retrieve hash\n");
		gcry_md_close(gcry_hash_hd);
		return 1;
	}

	/*
	 * Copy the first 128-bits of the 256-bit hash as our 128-bit random
	 * values. Destroy the original values in the process by overwriting
	 * them.
	 */

	memcpy(rand, digest, 16);

	gcry_md_close(gcry_hash_hd);

	printf("rdrand128:\n");
	hexdump(rand, 16);
}

