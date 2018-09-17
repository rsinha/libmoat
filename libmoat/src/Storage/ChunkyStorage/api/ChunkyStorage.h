#ifndef _CHUNKYSTORAGE_H_
#define _CHUNKYSTORAGE_H_

#include <stddef.h>
#include "sgx_tcrypto.h"
#include "../../../Utils/api/Utils.h"

uint64_t chunk_storage_payload_len(uint64_t len);
int64_t chunk_storage_write(cipher_ctx_t *ctx, uint8_t *dst, uint8_t *src, uint64_t src_len, uint64_t version, uint8_t *aad_prefix, uint64_t aad_prefix_len);
int64_t chunk_storage_read(cipher_ctx_t *ctx, uint64_t offset, uint8_t *buf,  uint64_t len, uint8_t *untrusted_buf, uint64_t version, uint8_t *aad_prefix, uint64_t aad_prefix_len);

#endif

