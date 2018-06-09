#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <inttypes.h>

#include "libmoat.h"
#include "common.h"

#include "sgx_dh.h"

int64_t load_category_db()
{
    int64_t dbd = _moat_kvs_open("tmp://cat_db", O_RDWR);
    _moat_print_debug("got kvs fd " PRId64 " for tmp://cat_db\n", dbd);
    assert(dbd != -1);

    uint64_t gmr[2] = {1, 2};
    uint64_t cat[2] = {1, 2};

    for (int i = 0; i < 2; i++)
    {
        kv_key_t k;
        memset(&k, 0, sizeof(k));
        memcpy(&k, &(gmr[i]), sizeof(gmr[i]));
        int64_t api_result = _moat_kvs_set(dbd, &k, 0, &(cat[i]), sizeof(cat[i]));
        assert (api_result == sizeof(cat[i]));
    }

    _moat_print_debug("sucessfully created category DB...\n");
    return dbd;
}

uint64_t enclave_test()
{
    _moat_debug_module_init();
    _moat_scc_module_init();
    _moat_kvs_module_init();

    //ideally some authority (e.g. CA) will tell us this
    sgx_measurement_t measurement = { .m = { 0x6A,0xD5,0x51,0xD6,0x40,0x9F,0xA1,0x9B,
                                             0x96,0x2A,0x5B,0x5B,0xCB,0x2E,0xD4,0x08,
                                             0x11,0xB8,0x86,0x5A,0x77,0x2A,0x53,0xEA,
                                             0x7D,0x56,0x45,0x10,0x51,0xD4,0x9C,0x52 } };
    scc_attributes_t attr = { .record_size = 128, .side_channel_protection = 0 };
    scc_handle_t *handle = _moat_scc_create(true, &measurement, &attr);
    assert(handle != NULL);
    _moat_print_debug("ECDHE+AES-GCM-128 channel established with client...\n");

    int64_t cat_db = load_category_db();
    _moat_print_debug("got kvs fd %ld for tmp://cat_db\n", cat_db);

    int64_t rprt_db = _moat_kvs_open("out://rprt", O_RDWR);
    _moat_print_debug("got kvs fd %ld for out://rprt\n", rprt_db);

    do {
        bool next;
        transaction_t tx;
        size_t api_result;

        //do we have another transaction?
        api_result = _moat_scc_recv(handle, &next, sizeof(bool));
        assert(api_result == 0);
        if (!next) { break; }
        _moat_print_debug("received tx...\n");

        //get the next transaction
        api_result = _moat_scc_recv(handle, &tx, sizeof(tx));
        assert(api_result == 0);

        //get category of the merchant in the input transaction
        kv_key_t k;
        memset(&k, 0, sizeof(k));
        memcpy(&k, &(tx.gmr_id), sizeof(tx.gmr_id));
        uint64_t cat;
        int64_t kvs_api_result = _moat_kvs_get(cat_db, &k, 0, &(cat), sizeof(cat));
        assert(kvs_api_result == sizeof(cat));
        _moat_print_debug("Searching for gmr %lu, got %lu\n", tx.gmr_id, cat);

        //update amt for the category
        kv_key_t cat_k;
        uint64_t amt = 0;
        memset(&cat_k, 0, sizeof(cat_k));
        memcpy(&cat_k, &(cat), sizeof(cat));
        kvs_api_result = _moat_kvs_get(rprt_db, &cat_k, 0, &(amt), sizeof(amt));
        amt += tx.amt;
        kvs_api_result = _moat_kvs_set(rprt_db, &cat_k, 0, &amt, sizeof(amt));
        assert(kvs_api_result == sizeof(amt));
        _moat_print_debug("processed tx...\n");
    } while(true);
    
    _moat_print_debug("done processing all txs\n");

    uint64_t cat[2] = {1, 2};

    for (int i = 0; i < 2; i++)
    {
        kv_key_t cat_k;
        memset(&cat_k, 0, sizeof(cat_k));
        memcpy(&cat_k, &(cat[i]), sizeof(cat[i]));
        uint64_t amt;
        int64_t api_result = _moat_kvs_get(rprt_db, &cat_k, 0, &(amt), sizeof(amt));
        if (api_result > 0) {
            _moat_print_debug("cat %lu, amt %lu\n", cat[i], amt);
        }
    }

    return 0;
}
