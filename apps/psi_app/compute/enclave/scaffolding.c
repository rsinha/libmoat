#include <assert.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>

#include "libmoat.h"

#include "sgx_dh.h"
#include "sgx_trts.h"

#include "record.pb-c.h"
#include "delivery.pb-c.h"
#include "specification.pb-c.h"
#include "ledgerentry.pb-c.h"


uint64_t f(bool); /* user-defined function */
bool phi(bool init);


bool state_policy(const Luciditee__Specification *spec, Luciditee__Record *record)
{
    for (size_t i = 0; i < spec->n_statevars; i++) {
        Luciditee__Specification__StateDescription *statevar = spec->statevars[i];
        Luciditee__Record__NamedDigest *nd = record->statevars[i];
        assert(nd->digest.len == sizeof(sgx_sha256_hash_t));
        assert(strcmp(nd->name, statevar->state_name) == 0);

        uint8_t *ledger_hash = ledger_hash = nd->digest.data;
        sgx_sha256_hash_t my_hash;
        if (statevar->type == LUCIDITEE__SPECIFICATION__TYPE__FILE) {
            int64_t fd = _moat_fs_open(nd->name, 0, NULL);
            assert(_moat_fs_get_digest(fd, &my_hash) == 0);
        } else if (statevar->type == LUCIDITEE__SPECIFICATION__TYPE__KVS) {
            int64_t fd = _moat_kvs_open(nd->name, 0, NULL);
            assert(_moat_kvs_get_digest(fd, &my_hash) == 0);
        }

        if (memcmp(ledger_hash, &my_hash, sizeof(sgx_sha256_hash_t)) != 0) {
            return false; //hash mismatches
        }
    }

    return true;
}

void generate_delivery_entry(const Luciditee__Specification *spec, uint64_t height, uint8_t **entry_buf, size_t *entry_buf_len)
{
    Luciditee__Delivery delivery;
    luciditee__delivery__init(&delivery);
    delivery.id = spec->id;
    delivery.t = height;

    sgx_aes_gcm_128bit_key_t output_key; memset(&output_key, 0, sizeof(output_key));
    delivery.encrypted_key.len = sizeof(sgx_aes_gcm_128bit_key_t);
    delivery.encrypted_key.data = (uint8_t *) &output_key;

    Luciditee__LedgerEntry ledger_entry;
    luciditee__ledger_entry__init(&ledger_entry);
    ledger_entry.type = LUCIDITEE__LEDGER_ENTRY__ENTRY_TYPE__DELIVER;
    ledger_entry.entry_case = LUCIDITEE__LEDGER_ENTRY__ENTRY_DELIVERY;
    ledger_entry.delivery =  &delivery;
    *entry_buf_len = luciditee__ledger_entry__get_packed_size(&ledger_entry);
    *entry_buf = (uint8_t *) malloc(*entry_buf_len);
    assert(*entry_buf != NULL);
    assert (luciditee__ledger_entry__pack(&ledger_entry, *entry_buf) == *entry_buf_len);
}

void print_digest(char *name, sgx_sha256_hash_t *buf)
{
    _moat_print_debug("%s digest: 0x", name); 
    for (size_t i = 0; i < sizeof(sgx_sha256_hash_t); i++) { 
        _moat_print_debug("%02x", ((uint8_t *) buf)[i]); 
    }
    _moat_print_debug("\n");
}

void get_digest(char *name, sgx_sha256_hash_t *buf, Luciditee__Specification__Type type)
{
    if (type == LUCIDITEE__SPECIFICATION__TYPE__FILE) {
        int64_t fd = _moat_fs_open(name, 0, NULL);
        assert(_moat_fs_get_digest(fd, buf) == 0);
    } else if (type == LUCIDITEE__SPECIFICATION__TYPE__KVS) {
        int64_t fd = _moat_kvs_open(name, 0, NULL);
        assert(_moat_kvs_get_digest(fd, buf) == 0);
    } else {
        assert(false); //TODO: right now only supporting 2 types
    }
}

void generate_computation_record(const Luciditee__Specification *spec, uint64_t height, uint8_t **entry_buf, size_t *entry_buf_len)
{
    _moat_print_debug("----------------------------\n");
    _moat_print_debug("record computation:\n");
    _moat_print_debug("computation id: %" PRIu64 "\n", spec->id);

    Luciditee__Record record;
    luciditee__record__init(&record);
    record.id = spec->id;
    record.t = height;
    
    record.n_inputs = spec->n_inputs;
    record.inputs = (Luciditee__Record__NamedDigest **) malloc(sizeof(void *) * record.n_inputs);
    assert(record.inputs != NULL);
    for (size_t i = 0; i < spec->n_inputs; i++) {
        Luciditee__Specification__InputDescription *input = spec->inputs[i];
        Luciditee__Record__NamedDigest *nd = (Luciditee__Record__NamedDigest *) 
            malloc(sizeof(Luciditee__Record__NamedDigest)); assert(nd != NULL);
        luciditee__record__named_digest__init(nd);
        nd->name = input->input_name;
        nd->digest.len = sizeof(sgx_sha256_hash_t);
        nd->digest.data = malloc(sizeof(sgx_sha256_hash_t));
        assert(nd->digest.data != NULL);
        get_digest(nd->name, (sgx_sha256_hash_t *) nd->digest.data, input->type);
        print_digest(nd->name, (sgx_sha256_hash_t *) nd->digest.data);
        record.inputs[i] = nd;
    }

    record.n_outputs = spec->n_outputs;
    record.outputs = (Luciditee__Record__NamedDigest **) malloc(sizeof(void *) * record.n_outputs);
    assert(record.outputs != NULL);
    for (size_t i = 0; i < spec->n_outputs; i++) {
        Luciditee__Specification__OutputDescription *output = spec->outputs[i];
        Luciditee__Record__NamedDigest *nd = (Luciditee__Record__NamedDigest *) 
            malloc(sizeof(Luciditee__Record__NamedDigest)); assert(nd != NULL);
        luciditee__record__named_digest__init(nd);
        nd->name = output->output_name;
        nd->digest.len = sizeof(sgx_sha256_hash_t);
        nd->digest.data = malloc(sizeof(sgx_sha256_hash_t));
        assert(nd->digest.data != NULL);
        get_digest(nd->name, (sgx_sha256_hash_t *) nd->digest.data, output->type);
        print_digest(nd->name, (sgx_sha256_hash_t *) nd->digest.data);
        record.outputs[i] = nd;
    }

    record.n_statevars = spec->n_statevars;
    record.statevars = (Luciditee__Record__NamedDigest **) malloc(sizeof(void *) * record.n_statevars);
    assert(record.statevars != NULL);
    for (size_t i = 0; i < spec->n_statevars; i++) {
        Luciditee__Specification__StateDescription *statevar = spec->statevars[i];
        Luciditee__Record__NamedDigest *nd = (Luciditee__Record__NamedDigest *) 
            malloc(sizeof(Luciditee__Record__NamedDigest)); assert(nd != NULL);
        luciditee__record__named_digest__init(nd);
        nd->name = statevar->state_name;
        nd->digest.len = sizeof(sgx_sha256_hash_t);
        nd->digest.data = malloc(sizeof(sgx_sha256_hash_t));
        assert(nd->digest.data != NULL);
        get_digest(nd->name, (sgx_sha256_hash_t *) nd->digest.data, statevar->type);
        print_digest(nd->name, (sgx_sha256_hash_t *) nd->digest.data);
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
        _moat_print_debug("attempting to open %s\n", input->input_name);
        if (input->type == LUCIDITEE__SPECIFICATION__TYPE__FILE) {
            int64_t fd = _moat_fs_open(input->input_name, O_RDONLY, &encr_key);
            assert(fd != -1);
        } else if (input->type == LUCIDITEE__SPECIFICATION__TYPE__KVS) {
            int64_t fd = _moat_kvs_open(input->input_name, O_RDONLY, &encr_key);
            assert(fd != -1);
        } else {
            assert(false);
        }
    }
    //print outputs
    for (size_t i = 0; i < spec->n_outputs; i++) {
        Luciditee__Specification__OutputDescription *output = spec->outputs[i];
        memset(&encr_key, 0, sizeof(encr_key));
        _moat_print_debug("attempting to open %s\n", output->output_name);
        if (output->type == LUCIDITEE__SPECIFICATION__TYPE__FILE) {
            int64_t fd = _moat_fs_open(output->output_name, O_RDWR | O_CREAT, &encr_key);
            assert(fd != -1);
        } else if (output->type == LUCIDITEE__SPECIFICATION__TYPE__KVS) {
            int64_t fd = _moat_kvs_open(output->output_name, O_RDWR | O_CREAT, &encr_key);
            assert(fd != -1);
        } else {
            assert(false);
        }
    }
    //print state
    for (size_t i = 0; i < spec->n_statevars; i++) {
        Luciditee__Specification__StateDescription *statevar = spec->statevars[i];
        memset(&encr_key, 0, sizeof(encr_key));
        _moat_print_debug("attempting to open %s\n", statevar->state_name);
        if (statevar->type == LUCIDITEE__SPECIFICATION__TYPE__FILE) {
            int64_t fd = _moat_fs_open(statevar->state_name, init ? O_RDWR | O_CREAT : O_RDWR, &encr_key);
            assert(fd != -1);
        } else if (statevar->type == LUCIDITEE__SPECIFICATION__TYPE__KVS) {
            int64_t fd = _moat_kvs_open(statevar->state_name, init ? O_RDWR | O_CREAT : O_RDWR, &encr_key);
            assert(fd != -1);
        } else {
            assert(false);
        }
    }
}

Luciditee__LedgerEntry *parse_buf_as_ledger_entry(uint8_t *buf, size_t buf_len)
{
    Luciditee__LedgerEntry *entry;
    entry = luciditee__ledger_entry__unpack(NULL, buf_len, buf);
    return entry;
}

void free_buf_of_ledger_entry_buf(Luciditee__LedgerEntry *entry)
{
    luciditee__ledger_entry__free_unpacked(entry, NULL);
}

bool is_entry_a_spec(Luciditee__LedgerEntry *entry)
{
    return entry->type == LUCIDITEE__LEDGER_ENTRY__ENTRY_TYPE__CREATE &&
            entry->entry_case == LUCIDITEE__LEDGER_ENTRY__ENTRY_SPEC;
}

bool is_entry_a_record(Luciditee__LedgerEntry *entry)
{
    return entry->type == LUCIDITEE__LEDGER_ENTRY__ENTRY_TYPE__RECORD &&
            entry->entry_case == LUCIDITEE__LEDGER_ENTRY__ENTRY_RECORD;
}

bool is_entry_of_spec_id(Luciditee__LedgerEntry *entry, uint64_t spec_id)
{
    if (is_entry_a_spec(entry)) {
        Luciditee__Specification *spec = entry->spec;
        return spec->id == spec_id;
    } else if (is_entry_a_record(entry)) {
        Luciditee__Record *record = entry->record;
        return record->id == spec_id;
    }
    return false;
}

uint64_t invoke_enclave_computation(uint64_t spec_id)
{
    /* initialize libmoat */
    _moat_debug_module_init();
    _moat_fs_module_init();
    _moat_kvs_module_init();

    bool found_spec = false, found_record = false;
    Luciditee__LedgerEntry *latest_record_entry;
    Luciditee__LedgerEntry *spec_entry;
    
    uint64_t height = _moat_l_get_current_counter();
    //_moat_print_debug("luciditee's ledger has height %" PRIu64 "\n", height);

    /*
    for (uint64_t t = 0; t < height; t++) {
        uint8_t *ledger_entry_buf = NULL; size_t ledger_entry_buf_len = 0;
        bool result = _moat_l_get_content(t, (void **) &ledger_entry_buf, &ledger_entry_buf_len);
        assert(result);

        Luciditee__LedgerEntry *entry = parse_buf_as_ledger_entry(ledger_entry_buf, ledger_entry_buf_len);
        assert(entry != NULL);

        if (is_entry_a_spec(entry) && is_entry_of_spec_id(entry, spec_id)) 
        {
            assert(found_spec == false); //sanity check
            spec_entry = entry;
            _moat_print_debug("found specification at ledger height %" PRIu64 "\n", t);
            found_spec = true;
        } 
        else if (is_entry_a_record(entry) && is_entry_of_spec_id(entry, spec_id)) 
        {
            if (found_record) //is this not the first record entry for this spec_id
            {
                free_buf_of_ledger_entry_buf(latest_record_entry);
            }
            latest_record_entry = entry;
            _moat_print_debug("found record at ledger height %" PRIu64 "\n", t);
            found_record = true;
        } 
        else 
        {
            free_buf_of_ledger_entry_buf(entry);
        }

        free(ledger_entry_buf);
    }
    */

    uint8_t *ledger_entry_buf = NULL; size_t ledger_entry_buf_len = 0;
    bool result = _moat_l_get_policy(spec_id, (void **) &ledger_entry_buf, &ledger_entry_buf_len);
    if (!result) {
        _moat_print_debug("unable to find specification with id %" PRIu64 "\n", spec_id);
        return -1;
    }
    Luciditee__LedgerEntry *entry = parse_buf_as_ledger_entry(ledger_entry_buf, ledger_entry_buf_len);
    assert(is_entry_a_spec(entry) && is_entry_of_spec_id(entry, spec_id));
    spec_entry = entry;

    bool result = _moat_l_get_compute_record(spec_id, (void **) &ledger_entry_buf, &ledger_entry_buf_len);
    if (result) {
        entry = parse_buf_as_ledger_entry(ledger_entry_buf, ledger_entry_buf_len);
        assert(is_entry_a_record(entry) && is_entry_of_spec_id(entry, spec_id));
        latest_record_entry = entry;
        found_record = true;
    }


    //if (!found_spec) {
    //    _moat_print_debug("unable to find specification with id %" PRIu64 "\n", spec_id);
    //    return -1;
    //}

    bool init = !found_record;
    if (init) { _moat_print_debug("treating this as initial step\n"); }

    /* open all the input, output, and state structures */
    open_files(spec_entry->spec, init);

    /* invoke policy checker */
    bool compliant;
    if (!init) {
        compliant = state_policy(spec_entry->spec, latest_record_entry->record);
        if (! compliant) {
            _moat_print_debug("state_policy check failed\n");
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

    /* generate the on-ledger record entry */
    uint8_t *record_buf; size_t record_buf_len;
    generate_computation_record(spec_entry->spec, height, &record_buf, &record_buf_len);
    /* post record on the ledger; libmoat also invokes verify_L for us */
    assert(_moat_l_post(record_buf, record_buf_len));

    /* generate the on-ledger delivery entry */
    uint8_t *delivery_buf; size_t delivery_buf_len;
    generate_delivery_entry(spec_entry->spec, height, &delivery_buf, &delivery_buf_len);
    /* post encrypted key on the ledger; libmoat also invokes verify_L for us */
    assert(_moat_l_post(delivery_buf, delivery_buf_len));

    return result;
}
