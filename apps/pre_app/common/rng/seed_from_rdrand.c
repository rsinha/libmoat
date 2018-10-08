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
#include <string.h>

#define AES_BLOCK_SIZE	16		/* AES uses 128-bit blocks (16 bytes) */
#define AES_KEY_SIZE	16		/* AES with 128-bit key (AES-128) */
#define	RDRAND_SAMPLES	512		/* the DRNG reseeds after generating 511
								 * 128-bit (16-byte) values */
#define BUFFER_SIZE		16*RDRAND_SAMPLES

#define MIN_GCRYPT_VERSION "1.0.0"

/*
 * Generates seed-grade entropy values from RDRAND. This works because
 * the DRNG reseeds automatically after generating 511 128-bit samples.
 * By cryptographically mixing intermediate RDRAND values and crossing
 * a reseed boundary, we can generate seed values in 128-bit blocks.
 * These seed values can be concatenated together to form arbitrarily
 * large seeds, and used to seed a PRNG of any size.
 *
 * For the AES reduction in this example, we'll make use libgcrypt.
 * In an application that needs lots of seeds, you can use AES-NI
 * directly to parallelize multiple block chains at the same time,
 * vastly increasing total throughput
 *
 * Do AES encryption in CBC-MAC mode. In CBC, every block of ciphertext
 * is a function of the previous block, so the final 128-bits of the 
 * ciphertext is a function of all previous blocks and that is both the
 * MAC and our 128-bit seed. 
 *
 * We'll generate a random key and IV using RDRAND. In "real" CBC-MAC
 * you use a zero IV in order to prevent an attacker from being able to
 * create collisions, but we are not really doing message authentication:
 * we're using the algorithm for randomness extraction. Generating a
 * random IV cannot hurt, and potentially helps.
 */

int main (int argc, char *argv[])
{
	unsigned char rbuffer[BUFFER_SIZE];
	unsigned char aes_key[AES_KEY_SIZE];
	unsigned char aes_iv[AES_KEY_SIZE];
	unsigned char seed[16];
	static gcry_cipher_hd_t gcry_cipher_hd;
	gcry_error_t gcry_error;

	if ( ! ( get_drng_support() & DRNG_HAS_RDRAND ) ) {
		fprintf(stderr, "No RDRAND support\n");
		return 1;
	}

	/* Generate a random AES key */

	if ( rdrand_get_bytes(AES_KEY_SIZE, aes_key) < AES_KEY_SIZE ) {
		fprintf(stderr, "Random numbers not available\n");
		return 1;
	}

	/* Generate a random IV */

	if ( rdrand_get_bytes(AES_BLOCK_SIZE, aes_iv) < AES_BLOCK_SIZE ) {
		fprintf(stderr, "Random numbers not available\n");
		return 1;
	}

	/*
	 * Fill our buffer with 512 128-bit rdrands. This guarantees that
	 * /at least/ one reseed takes place.
	 */

	if ( rdrand_get_bytes(BUFFER_SIZE, rbuffer) < BUFFER_SIZE ) {
		fprintf(stderr, "Random numbers not available\n");
		return 1;
	}

	/* Initialize the cryptographic library */

	if (!gcry_check_version(MIN_GCRYPT_VERSION)) {
		fprintf(stderr,
			"gcry_check_version: have version %s, need version %s or newer",
			gcry_check_version(NULL), MIN_GCRYPT_VERSION
		);

		return 1;
	}

	gcry_error= gcry_cipher_open(&gcry_cipher_hd, GCRY_CIPHER_AES128,
		GCRY_CIPHER_MODE_CBC, 0);
	if ( gcry_error ) {
		fprintf(stderr, "gcry_cipher_open: %s", gcry_strerror(gcry_error));
		return 1;
	}

	gcry_error= gcry_cipher_setkey(gcry_cipher_hd, aes_key, AES_KEY_SIZE);
	if ( gcry_error ) { 
		fprintf(stderr, "gcry_cipher_setkey: %s", gcry_strerror(gcry_error));
		gcry_cipher_close(gcry_cipher_hd);
		return 1;
	}

	gcry_error= gcry_cipher_setiv(gcry_cipher_hd, aes_iv, AES_BLOCK_SIZE);
	if ( gcry_error ) { 
		fprintf(stderr, "gcry_cipher_setiv: %s", gcry_strerror(gcry_error));
		gcry_cipher_close(gcry_cipher_hd);
		return 1;
	}

	/* 
	 * Do the encryption in-place. This has the nice side effect of 
	 * erasing the original values.
	 */

	gcry_error= gcry_cipher_encrypt(gcry_cipher_hd, rbuffer, BUFFER_SIZE,
		NULL, 0);
	if ( gcry_error ) {
		fprintf(stderr, "gcry_cipher_encrypt: %s\n",
			gcry_strerror(gcry_error));
		return 1;
	}

	gcry_cipher_close(gcry_cipher_hd);

	/* The last block of the cipher text is the MAC, and our seed value. */

	memcpy(seed, &rbuffer[BUFFER_SIZE-16], 16);

	printf("Seed:\n");
	hexdump(seed, 16);
}

