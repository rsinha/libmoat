#include <assert.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>
#include "libmoat.h"
#include "common.h"
#include "Crypto/bitops.h"
#include "Crypto/pbkdf2.h"
#include "Crypto/sha2.h"
#include "Crypto/handy.h"
#include <stdarg.h>
#include <stdio.h>
#include "sgx_dh.h"
#include "sgx_trts.h"
#include "interface_t.h"

typedef struct
{
    #define PWRECORD_VERSION 1
	uint32_t version;
    #define PWRECORD_PBKDF2_ITERS 50000
	uint32_t iters;
	uint8_t salt[16];
	uint8_t hash[32];
} pwrecord;

static void pwrecord_clean(pwrecord *pwr) {
    mem_clean(pwr, sizeof *pwr);
}

static uint32_t pwrecord_new(pwrecord *pwr) {
    pwr->version = 1;
    pwr->iters = 50000;
    if (sgx_read_rand(pwr->salt, sizeof pwr->hash) != SGX_SUCCESS) {
        return 0;
    }
    memset(pwr->hash, 0, sizeof pwr->hash);
    return 1;
    
}

static void pwrecord_compute_hash(const pwrecord *pwr, const uint8_t *password,
		uint32_t pwlen, uint8_t out[32]) {
    cf_pbkdf2_hmac(password, pwlen, pwr->salt, sizeof pwr->salt, pwr->iters,
                    out, 32, &cf_sha256);

}
static void pwrecord_fill_hash(pwrecord *pwr, const uint8_t *password,
	uint32_t pwlen) {
    pwrecord_compute_hash(pwr, password, pwlen, pwr->hash);
}
static void pwrecord_encode(pwrecord *pwr, uint8_t* out) {
    uint8_t* outclone = out;
    write32_be(pwr->version, outclone);
    outclone+=4;
    write32_be(pwr->iters, outclone);
    outclone+=4;
    memcpy(outclone, pwr->salt, sizeof pwr->salt);
    outclone+=16;
    memcpy(outclone, pwr->hash, sizeof pwr->hash);
}

static uint32_t pwrecord_decode(pwrecord *pwr, const uint8_t *buf) {
   _moat_print_debug("here\n");
   pwr->version = read32_be(buf);
   pwr->iters = read32_be(buf+4);
   memcpy(pwr->salt, buf+8, sizeof pwr->salt);
   memcpy(pwr->hash, buf + 8 + sizeof pwr-> salt, sizeof pwr->hash);
   if (pwr->version != PWRECORD_VERSION || pwr->iters == 0) {
        return 0; 
    }
    return 1;
}

static uint32_t pwrecord_check_pass(pwrecord *pwr, const uint8_t *password,
 	uint32_t pwlen) {
    uint8_t purported[32];
    pwrecord_compute_hash(pwr, password, pwlen, purported);
    if (memcmp(pwr->hash, purported, sizeof pwr->hash) == 0) {
        _moat_print_debug("equal\n");
        return 1;
    }
    _moat_print_debug("%s\n", pwr->hash);
    _moat_print_debug("%s\n", purported);
    _moat_print_debug("not equal\n");
    return 0;

}
uint64_t pw_setup(uint8_t* password, uint32_t passlen, uint8_t* user, 
	uint32_t userlen) {
        pwrecord pwr = { 0 };
        uint32_t err = pwrecord_new(&pwr);
	if (err == 0) {
            return err;
	}
        uint8_t blob[56];
        pwrecord_fill_hash(&pwr, password, 5);
        pwrecord_encode(&pwr, blob);
        fs_handle_t *fd = _moat_fs_open(user);
        _moat_fs_write(fd, 0, &blob, sizeof(blob));
        _moat_print_debug("set up info recieved\n");
        return 1;
}
uint64_t pw_check() {
    uint8_t password[5];
    uint8_t user[5];
    //ideally some authority (e.g. CA) will tell us this
    sgx_measurement_t measurement = { .m = { 0x55,0xCF,0x87,0x7E,0xFF,0x2F,0xE4,0x09,
                                             0x6F,0x16,0x5B,0xC1,0x0D,0x06,0xCB,0x7A,
                                             0xAF,0x49,0xEF,0x4B,0xCE,0xBD,0xEA,0x90,
                                             0xD6,0x28,0x98,0xBC,0xBC,0x8F,0x50,0x36 } };
    scc_attributes_t attr = { .record_size = 128, .side_channel_protection = 0 };

    scc_handle_t *handle = _moat_scc_create(true, &measurement, &attr);
    _moat_scc_recv(handle, user, 5);
    _moat_scc_recv(handle, password, 5);
    int api_result = _moat_scc_destroy(handle); assert(api_result == 0);
    pwrecord pwr = { 0 };
    uint32_t err;
    if (err == 0) {
        return err;
    }
    uint8_t orig[56];
    fs_handle_t *fd = _moat_fs_open(user);
    _moat_fs_read(fd, 0, orig, 56);
    pwrecord_decode(&pwr, password);
    err = pwrecord_check_pass(&pwr, password, sizeof password);
    pwrecord_clean(&pwr);
    _moat_print_debug("check info recieved: %d\n", err);
    return err;

}


uint64_t pw_starter() {
     _moat_print_debug("Entered starter\n");
     sgx_measurement_t measurement = { .m = { 0x6A,0xD5,0x51,0xD6,0x40,0x9F,0xA1,0x9B,
                                             0x96,0x2A,0x5B,0x5B,0xCB,0x2E,0xD4,0x08,
                                             0x11,0xB8,0x86,0x5A,0x77,0x2A,0x53,0xEA,
                                             0x7D,0x56,0x45,0x10,0x51,0xD4,0x9C,0x52 } };
    scc_attributes_t attr = { .record_size = 128, .side_channel_protection = 0 };
    scc_handle_t *handle = _moat_scc_create(true, &measurement, &attr);
    _moat_print_debug("Created SCC\n");
    uint8_t user[5];
    uint8_t password[5];
    uint8_t user2[5];
    uint8_t pass2[5];
    uint8_t user3[5];
    uint8_t pass3[5];
    _moat_scc_recv(handle, user, 5);
    _moat_scc_recv(handle, password, 5);
    _moat_scc_recv(handle, user2, 5);
    _moat_scc_recv(handle, pass2, 5);
    _moat_scc_recv(handle, user3, 5);
    _moat_scc_recv(handle, pass3, 5);
    _moat_print_debug("%s\n", password);
    int api_result = _moat_scc_destroy(handle); assert(api_result == 0);
}


uint64_t enclave_test()
{
    _moat_debug_module_init();
    _moat_scc_module_init();
    _moat_fs_module_init();
    //ideally some authority (e.g. CA) will tell us this
    sgx_measurement_t measurement = { .m = { 0x6A,0xD5,0x51,0xD6,0x40,0x9F,0xA1,0x9B,
                                             0x96,0x2A,0x5B,0x5B,0xCB,0x2E,0xD4,0x08,
                                             0x11,0xB8,0x86,0x5A,0x77,0x2A,0x53,0xEA,
                                             0x7D,0x56,0x45,0x10,0x51,0xD4,0x9C,0x52 } };
    scc_attributes_t attr = { .record_size = 128, .side_channel_protection = 0 };
    scc_handle_t *handle = _moat_scc_create(true, &measurement, &attr);
    assert(handle != NULL);
    _moat_print_debug("ECDHE+AES-GCM-128 channel established with client...\n");

    blob_t blob;
    size_t api_result;
   
    //api_result = _moat_scc_recv(handle, &blob.x1, sizeof(blob.x1)); assert(api_result == 0);
    //api_result = _moat_scc_recv(handle, &blob.x2, sizeof(blob.x2)); assert(api_result == 0);
    api_result = _moat_scc_recv(handle, &blob, sizeof(blob)); assert(api_result == 0);
    api_result = _moat_print_debug("Received input...\n"); assert(api_result == 0);
    uint64_t result = blob.x1 + blob.x2;
    api_result = _moat_scc_send(handle, &result, sizeof(result)); assert(api_result == 0);
    api_result = _moat_print_debug("Sent result...\n"); assert(api_result == 0);
    api_result = _moat_scc_destroy(handle); assert(api_result == 0);
    return 0;
}

char* enclave_encrypt(char *password) {
    _moat_debug_module_init();
    _moat_scc_module_init();
    sgx_measurement_t measurement = { .m = { 0x6A,0xD5,0x51,0xD6,0x40,0x9F,0xA1,0x9B,
                                             0x96,0x2A,0x5B,0x5B,0xCB,0x2E,0xD4,0x08,
                                             0x11,0xB8,0x86,0x5A,0x77,0x2A,0x53,0xEA,
                                             0x7D,0x56,0x45,0x10,0x51,0xD4,0x9C,0x52 } };
    scc_attributes_t attr = { .record_size = 128, .side_channel_protection = 0 };
    scc_handle_t *handle = _moat_scc_create(true, &measurement, &attr);
    assert(handle != NULL);
    


    return 0;
}

