#include <assert.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>

#include "libmoat.h"

#include "sgx_dh.h"
#include "sgx_trts.h"

#include "record.pb-c.h"
#include "specification.pb-c.h"
#include "ledgerentry.pb-c.h"

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t SGX_CDECL ledger_post_ocall(size_t* retval, void* buf, size_t len);
sgx_status_t SGX_CDECL ledger_get_ocall(size_t* retval, void **untrusted_buf, size_t *untrusted_buf_len);

#ifdef __cplusplus
}
#endif

uint64_t f(bool); /* user-defined function */
bool phi(bool init);


void print_digest(const char *name, int64_t fd)
{
    sgx_sha256_hash_t hash;
    int64_t result = _moat_fs_get_digest(fd, &hash);
    if (result != 0) { return; }
    _moat_print_debug("%s digest: 0x", name); 
    for (size_t i = 0; i < sizeof(hash); i++) { 
        _moat_print_debug("%02x", ((uint8_t *) hash)[i]); 
    }
    _moat_print_debug("\n");
}

bool state_policy(uint8_t *entry_buf, size_t entry_buf_len)
{
    Luciditee__LedgerEntry *ledger_entry;
    ledger_entry = luciditee__ledger_entry__unpack(NULL, entry_buf_len, entry_buf);
    assert(ledger_entry != NULL);
    assert(ledger_entry->type == LUCIDITEE__LEDGER_ENTRY__ENTRY_TYPE__RECORD);
    assert(ledger_entry->entry_case == LUCIDITEE__LEDGER_ENTRY__ENTRY_RECORD);

    Luciditee__Record *record = ledger_entry->record;

    for (size_t i = 0; i < record->n_statevars; i++) {
        Luciditee__Record__NamedDigest *nd = record->statevars[i];
        assert(nd->digest.len == sizeof(sgx_sha256_hash_t));
        int64_t fd = _moat_fs_open(nd->name, 0, NULL);
        uint8_t *ledger_hash = nd->digest.data;
        sgx_sha256_hash_t my_hash;
        assert(_moat_fs_get_digest(fd, &my_hash) == 0);
        if (memcmp(ledger_hash, &my_hash, sizeof(sgx_sha256_hash_t)) != 0) {
            return false; //hash mismatches
        }
    }

    luciditee__ledger_entry__free_unpacked(ledger_entry, NULL);
    return true;
}

void generate_computation_record(const Luciditee__Specification *spec, uint8_t **entry_buf, size_t *entry_buf_len)
{
    _moat_print_debug("----------------------------\n");
    _moat_print_debug("record computation:\n");
    _moat_print_debug("computation id: %" PRIu64 "\n", spec->id);

    Luciditee__Record record;
    luciditee__record__init(&record);
    record.id = spec->id;
    record.t = 0;
    
    record.n_inputs = spec->n_inputs;
    record.inputs = (Luciditee__Record__NamedDigest **) malloc(sizeof(void *) * record.n_inputs);
    for (size_t i = 0; i < spec->n_inputs; i++) {
        Luciditee__Specification__InputDescription *input = spec->inputs[i];
        Luciditee__Record__NamedDigest *nd = (Luciditee__Record__NamedDigest *) 
            malloc(sizeof(Luciditee__Record__NamedDigest)); assert(nd != NULL);
        luciditee__record__named_digest__init(nd);
        nd->name = input->input_name;
        nd->digest.len = sizeof(sgx_sha256_hash_t);
        nd->digest.data = malloc(sizeof(sgx_sha256_hash_t)); assert(nd->digest.data != NULL);
        int64_t fd = _moat_fs_open(nd->name, 0, NULL);
        print_digest(nd->name, fd);
        assert(_moat_fs_get_digest(fd, (sgx_sha256_hash_t *) nd->digest.data) == 0);
        record.inputs[i] = nd;
    }

    record.n_outputs = spec->n_outputs;
    record.outputs = (Luciditee__Record__NamedDigest **) malloc(sizeof(void *) * record.n_outputs);
    for (size_t i = 0; i < spec->n_outputs; i++) {
        Luciditee__Specification__OutputDescription *output = spec->outputs[i];
        Luciditee__Record__NamedDigest *nd = (Luciditee__Record__NamedDigest *) 
            malloc(sizeof(Luciditee__Record__NamedDigest)); assert(nd != NULL);
        luciditee__record__named_digest__init(nd);
        nd->name = output->output_name;
        nd->digest.len = sizeof(sgx_sha256_hash_t);
        nd->digest.data = malloc(sizeof(sgx_sha256_hash_t)); assert(nd->digest.data != NULL);
        int64_t fd = _moat_fs_open(nd->name, 0, NULL);
        print_digest(nd->name, fd);
        assert(_moat_fs_get_digest(fd, (sgx_sha256_hash_t *) nd->digest.data) == 0);
        record.outputs[i] = nd;
    }

    record.n_statevars = spec->n_statevars;
    record.statevars = (Luciditee__Record__NamedDigest **) malloc(sizeof(void *) * record.n_statevars);
    for (size_t i = 0; i < spec->n_statevars; i++) {
        Luciditee__Specification__StateDescription *statevar = spec->statevars[i];
        Luciditee__Record__NamedDigest *nd = (Luciditee__Record__NamedDigest *) 
            malloc(sizeof(Luciditee__Record__NamedDigest)); assert(nd != NULL);
        luciditee__record__named_digest__init(nd);
        nd->name = statevar->state_name;
        nd->digest.len = sizeof(sgx_sha256_hash_t);
        nd->digest.data = malloc(sizeof(sgx_sha256_hash_t)); assert(nd->digest.data != NULL);
        int64_t fd = _moat_fs_open(nd->name, 0, NULL);
        print_digest(nd->name, fd);
        assert(_moat_fs_get_digest(fd, (sgx_sha256_hash_t *) nd->digest.data) == 0);
        record.statevars[i] = nd;
    }

    _moat_print_debug("----------------------------\n");

    Luciditee__LedgerEntry ledger_entry;
    luciditee__ledger_entry__init(&ledger_entry);
    ledger_entry.type = LUCIDITEE__LEDGER_ENTRY__ENTRY_TYPE__RECORD;
    ledger_entry.entry_case = LUCIDITEE__LEDGER_ENTRY__ENTRY_RECORD;
    ledger_entry.record = &record;
    *entry_buf_len = luciditee__ledger_entry__get_packed_size(&ledger_entry);
    *entry_buf = (uint8_t *) malloc(*entry_buf_len); assert(*entry_buf != NULL);
    assert (luciditee__ledger_entry__pack(&ledger_entry, *entry_buf) == *entry_buf_len);
}

void open_files(const Luciditee__Specification *spec, bool init)
{
    //open inputs
    sgx_aes_gcm_128bit_key_t encr_key;

    for (size_t i = 0; i < spec->n_inputs; i++) {
        Luciditee__Specification__InputDescription *input = spec->inputs[i];
        memset(&encr_key, 0, sizeof(encr_key));
        int64_t fd = _moat_fs_open(input->input_name, O_RDONLY, &encr_key);
        assert(fd != -1);
    }
    //print outputs
    for (size_t i = 0; i < spec->n_outputs; i++) {
        Luciditee__Specification__OutputDescription *output = spec->outputs[i];
        memset(&encr_key, 0, sizeof(encr_key));
        int64_t fd = _moat_fs_open(output->output_name, O_RDWR | O_CREAT, &encr_key);
        assert(fd != -1);
    }
    //print state
    for (size_t i = 0; i < spec->n_statevars; i++) {
        Luciditee__Specification__StateDescription *statevar = spec->statevars[i];
        memset(&encr_key, 0, sizeof(encr_key));
        int64_t fd = _moat_fs_open(statevar->state_name, init ? O_RDWR | O_CREAT : O_RDWR, &encr_key);
        print_digest(statevar->state_name, fd);
    }
}

Luciditee__LedgerEntry *parse_buf_as_entry(uint8_t *spec_buf, size_t spec_buf_len)
{
    Luciditee__LedgerEntry *entry;
    entry = luciditee__ledger_entry__unpack(NULL, spec_buf_len, spec_buf);
    assert(entry->type == LUCIDITEE__LEDGER_ENTRY__ENTRY_TYPE__CREATE);
    assert(entry->entry_case == LUCIDITEE__LEDGER_ENTRY__ENTRY_SPEC);
    return entry;
}

uint64_t invoke_enclave_computation(uint8_t *spec_buf, size_t spec_buf_len, bool init)
{
    /* initialize libmoat */
    _moat_debug_module_init();
    _moat_fs_module_init();

    Luciditee__LedgerEntry *entry = parse_buf_as_entry(spec_buf, spec_buf_len);
    Luciditee__Specification *spec = entry->spec;

    /* open all the input, output, and state structures */
    open_files(spec, init);

    size_t retstatus;
    uint8_t *untrusted_buf = NULL; size_t untrusted_buf_len = 0;
    uint8_t *ledger_entry_buf = NULL; size_t ledger_entry_buf_len = 0;
    if (init == false) {
        sgx_status_t status = ledger_get_ocall(&retstatus, (void **) &untrusted_buf, &untrusted_buf_len);
        assert(status == SGX_SUCCESS && retstatus == 0);
        ledger_entry_buf_len = untrusted_buf_len;
        ledger_entry_buf = (uint8_t *) malloc(ledger_entry_buf_len);
        assert(ledger_entry_buf != NULL);
        memcpy(ledger_entry_buf, untrusted_buf, ledger_entry_buf_len);
    }

    /* invoke policy checker */
    bool compliant;
    if (!init) {
        compliant = state_policy(ledger_entry_buf, ledger_entry_buf_len);
        if (! compliant) {
            _moat_print_debug("state_policy check failed");
            return -1;
        }
    }

    compliant = phi(init);
    if (!compliant) {
        _moat_print_debug("user defined policy check failed\n");
        return -1;
    }
    /* use the ledger to decide whether we are creating initial state, and let f know that */
    uint64_t result = f(init);

    /* generate the on-ledger record */
    uint8_t *record_buf; size_t record_buf_len;
    generate_computation_record(spec, &record_buf, &record_buf_len);

    sgx_status_t status = ledger_post_ocall(&retstatus, record_buf, record_buf_len);
    assert(status == SGX_SUCCESS && retstatus == 0);

    return result;
}
