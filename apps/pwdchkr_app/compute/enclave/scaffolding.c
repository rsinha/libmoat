#include <assert.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>

#include "libmoat.h"

#include "sgx_dh.h"
#include "sgx_trts.h"

#include "record.pb-c.h"
#include "specification.pb-c.h"


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

/*
void print_record_computation(uint8_t *spec_buf, size_t spec_buf_len)
{   
    LuciditeeGuessApp__Specification *spec;
    spec = luciditee_guess_app__specification__unpack(NULL, spec_buf_len, spec_buf);
    assert(spec != NULL);

    //print id
    _moat_print_debug("----------------------------\n");
    _moat_print_debug("record computation:\n");
    _moat_print_debug("spec has id: %" PRIu64 "\n", spec->id);
    //print inputs
    for (size_t i = 0; i < spec->n_inputs; i++) {
        LuciditeeGuessApp__Specification__InputDescription *input = spec->inputs[i];
        int64_t fd = _moat_fs_open(input->input_name, 0, NULL);
        print_digest(input->input_name, fd);
    }
    //print outputs
    for (size_t i = 0; i < spec->n_outputs; i++) {
        LuciditeeGuessApp__Specification__OutputDescription *output = spec->outputs[i];
        //_moat_print_debug("spec has output: %s\n", output->output_name);
        int64_t fd = _moat_fs_open(output->output_name, 0, NULL);
        print_digest(output->output_name, fd);
    }
    //print state
    for (size_t i = 0; i < spec->n_statevars; i++) {
        LuciditeeGuessApp__Specification__StateDescription *statevar = spec->statevars[i];
        //_moat_print_debug("spec has state var: %s\n", statevar->state_name);
        int64_t fd = _moat_fs_open(statevar->state_name, 0, NULL);
        print_digest(statevar->state_name, fd);
    }
    _moat_print_debug("----------------------------\n");

    luciditee_guess_app__specification__free_unpacked(spec, NULL);
}
*/

bool state_policy(uint8_t *buf, size_t buf_len)
{
    LuciditeeGuessApp__Record *record;
    record = luciditee_guess_app__record__unpack(NULL, buf_len, buf);
    assert(record != NULL);

    for (size_t i = 0; i < record->n_statevars; i++) {
        LuciditeeGuessApp__Record__NamedDigest *nd = record->statevars[i];
        assert(nd->digest.len == sizeof(sgx_sha256_hash_t));
        int64_t fd = _moat_fs_open(nd->name, 0, NULL);
        uint8_t *ledger_hash = nd->digest.data;
        sgx_sha256_hash_t my_hash;
        assert(_moat_fs_get_digest(fd, &my_hash) == 0);
        if (memcmp(ledger_hash, &my_hash, sizeof(sgx_sha256_hash_t)) != 0) {
            return false; //hash mismatches
        }
    }

    luciditee_guess_app__record__free_unpacked(record, NULL);
    return true;
}

void generate_computation_record(uint8_t *spec_buf, size_t spec_buf_len, uint8_t **record_buf, size_t *record_buf_len)
{
    LuciditeeGuessApp__Specification *spec;
    spec = luciditee_guess_app__specification__unpack(NULL, spec_buf_len, spec_buf);
    assert(spec != NULL);

    _moat_print_debug("----------------------------\n");
    _moat_print_debug("record computation:\n");
    _moat_print_debug("computation id: %" PRIu64 "\n", spec->id);

    LuciditeeGuessApp__Record record;
    luciditee_guess_app__record__init(&record);
    record.id = spec->id;
    record.t = 0;
    
    record.n_inputs = spec->n_inputs;
    record.inputs = (LuciditeeGuessApp__Record__NamedDigest **) malloc(sizeof(void *) * record.n_inputs);
    for (size_t i = 0; i < spec->n_inputs; i++) {
        LuciditeeGuessApp__Specification__InputDescription *input = spec->inputs[i];
        LuciditeeGuessApp__Record__NamedDigest *nd = (LuciditeeGuessApp__Record__NamedDigest *) 
            malloc(sizeof(LuciditeeGuessApp__Record__NamedDigest)); assert(nd != NULL);
        luciditee_guess_app__record__named_digest__init(nd);
        nd->name = input->input_name;
        nd->digest.len = sizeof(sgx_sha256_hash_t);
        nd->digest.data = malloc(sizeof(sgx_sha256_hash_t)); assert(nd->digest.data != NULL);
        int64_t fd = _moat_fs_open(nd->name, 0, NULL);
        print_digest(nd->name, fd);
        assert(_moat_fs_get_digest(fd, (sgx_sha256_hash_t *) nd->digest.data) == 0);
        record.inputs[i] = nd;
    }

    record.n_outputs = spec->n_outputs;
    record.outputs = (LuciditeeGuessApp__Record__NamedDigest **) malloc(sizeof(void *) * record.n_outputs);
    for (size_t i = 0; i < spec->n_outputs; i++) {
        LuciditeeGuessApp__Specification__OutputDescription *output = spec->outputs[i];
        LuciditeeGuessApp__Record__NamedDigest *nd = (LuciditeeGuessApp__Record__NamedDigest *) 
            malloc(sizeof(LuciditeeGuessApp__Record__NamedDigest)); assert(nd != NULL);
        luciditee_guess_app__record__named_digest__init(nd);
        nd->name = output->output_name;
        nd->digest.len = sizeof(sgx_sha256_hash_t);
        nd->digest.data = malloc(sizeof(sgx_sha256_hash_t)); assert(nd->digest.data != NULL);
        int64_t fd = _moat_fs_open(nd->name, 0, NULL);
        print_digest(nd->name, fd);
        assert(_moat_fs_get_digest(fd, (sgx_sha256_hash_t *) nd->digest.data) == 0);
        record.outputs[i] = nd;
    }

    record.n_statevars = spec->n_statevars;
    record.statevars = (LuciditeeGuessApp__Record__NamedDigest **) malloc(sizeof(void *) * record.n_statevars);
    for (size_t i = 0; i < spec->n_statevars; i++) {
        LuciditeeGuessApp__Specification__StateDescription *statevar = spec->statevars[i];
        LuciditeeGuessApp__Record__NamedDigest *nd = (LuciditeeGuessApp__Record__NamedDigest *) 
            malloc(sizeof(LuciditeeGuessApp__Record__NamedDigest)); assert(nd != NULL);
        luciditee_guess_app__record__named_digest__init(nd);
        nd->name = statevar->state_name;
        nd->digest.len = sizeof(sgx_sha256_hash_t);
        nd->digest.data = malloc(sizeof(sgx_sha256_hash_t)); assert(nd->digest.data != NULL);
        int64_t fd = _moat_fs_open(nd->name, 0, NULL);
        print_digest(nd->name, fd);
        assert(_moat_fs_get_digest(fd, (sgx_sha256_hash_t *) nd->digest.data) == 0);
        record.statevars[i] = nd;
    }

    *record_buf_len = luciditee_guess_app__record__get_packed_size(&record);
    *record_buf = (uint8_t *) malloc(*record_buf_len); assert(*record_buf != NULL);
    assert (luciditee_guess_app__record__pack(&record, *record_buf) == *record_buf_len);

    _moat_print_debug("----------------------------\n");

    luciditee_guess_app__specification__free_unpacked(spec, NULL);
}

void open_files(uint8_t *spec_buf, size_t spec_buf_len, bool init)
{   
    LuciditeeGuessApp__Specification *spec;
    spec = luciditee_guess_app__specification__unpack(NULL, spec_buf_len, spec_buf);
    assert(spec != NULL);

    //open inputs
    sgx_aes_gcm_128bit_key_t encr_key;

    for (size_t i = 0; i < spec->n_inputs; i++) {
        LuciditeeGuessApp__Specification__InputDescription *input = spec->inputs[i];
        memset(&encr_key, 0, sizeof(encr_key));
        int64_t fd = _moat_fs_open(input->input_name, O_RDONLY, &encr_key);
        assert(fd != -1);
    }
    //print outputs
    for (size_t i = 0; i < spec->n_outputs; i++) {
        LuciditeeGuessApp__Specification__OutputDescription *output = spec->outputs[i];
        memset(&encr_key, 0, sizeof(encr_key));
        int64_t fd = _moat_fs_open(output->output_name, O_RDWR | O_CREAT, &encr_key);
        assert(fd != -1);
    }
    //print state
    for (size_t i = 0; i < spec->n_statevars; i++) {
        LuciditeeGuessApp__Specification__StateDescription *statevar = spec->statevars[i];
        memset(&encr_key, 0, sizeof(encr_key));
        int64_t fd = _moat_fs_open(statevar->state_name, init ? O_RDWR | O_CREAT : O_RDWR, &encr_key);
        print_digest(statevar->state_name, fd);
    }

    luciditee_guess_app__specification__free_unpacked(spec, NULL);
}

/* TODO: eventually init arg will go away in lieu of a ledger */
uint64_t invoke_enclave_computation(uint8_t *spec_buf, size_t spec_buf_len, bool init)
{
    /* initialize libmoat */
    _moat_debug_module_init();
    _moat_fs_module_init();

    /* open all the input, output, and state structures */
    open_files(spec_buf, spec_buf_len, init);

    size_t retstatus;
    uint8_t *untrusted_buf = NULL; size_t untrusted_buf_len = 0;
    uint8_t *prev_record_buf = NULL;
    if (init == false) {
        sgx_status_t status = ledger_get_ocall(&retstatus, (void **) &untrusted_buf, &untrusted_buf_len);
        assert(status == SGX_SUCCESS && retstatus == 0);
        prev_record_buf = (uint8_t *) malloc(untrusted_buf_len);
        assert(prev_record_buf != NULL);
        memcpy(prev_record_buf, untrusted_buf, untrusted_buf_len);
    }

    /* invoke policy checker */
    bool compliant;
    if (!init) {
        compliant = state_policy(prev_record_buf, untrusted_buf_len);
        if (! compliant) {
            _moat_print_debug("state_policy check failed");
            return -1;
        }
    }

    compliant = phi(init);
    _moat_print_debug("finished compliance\n");
    if (!compliant) {
        _moat_print_debug("user defined policy check failed\n");
        return -1;
    }
    _moat_print_debug("about to invoke f\n");
    /* use the ledger to decide whether we are creating initial state, and let f know that */
    uint64_t result = f(init);

    /* generate the on-ledger record */
    uint8_t *record_buf; size_t record_buf_len;
    generate_computation_record(spec_buf, spec_buf_len, &record_buf, &record_buf_len);

    sgx_status_t status = ledger_post_ocall(&retstatus, record_buf, record_buf_len);
    assert(status == SGX_SUCCESS && retstatus == 0);

    return result;
}