#include <assert.h>
#include <stddef.h>
#include <inttypes.h>

#include "libmoat.h"
#include "common.h"

#include "sgx_dh.h"

uint64_t enclave_test()
{
    blob_t blob;
    char x;
    sgx_measurement_t measurement;
    scc_ctx_t *ctx = _moat_scc_create(true, &measurement);
    _moat_print_debug("Channel Established with client...");

    //server used for adding 1 to the secret input
    _moat_scc_send(ctx, &x, 1);
    _moat_scc_recv(ctx, &blob, sizeof(blob));
    _moat_print_debug("Received result...");
    _moat_print_debug("input: %" PRIu64, blob.x);
    blob.x += 1;
    _moat_scc_send(ctx, &blob, sizeof(blob));
    _moat_print_debug("Sent result...");

    return 0;
}

uint32_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t* peer_enclave_identity)
{
  return 0;
}

