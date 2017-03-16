#include "sgx_trts.h"
#include "sgx_utils.h"
#include "sgx_eid.h"
#include "sgx_ecp_types.h"
#include "sgx_thread.h"
#include "sgx_dh.h"
#include "sgx_tcrypto.h"

#include <assert.h>
#include <string.h>
#include <stdbool.h>

#include "api/RecordChannel.h"
#include "../../Utils/api/Utils.h"
#include "../../../api/libmoat_untrusted.h"

/***************************************************
 DEFINITIONS FOR INTERNAL USE
 ***************************************************/

#define MAX_SESSION_COUNT  16

/***************************************************
 INTERNAL STATE
 ***************************************************/

//Map between the source enclave id and the session information associated with that particular session
static ll_t *g_dest_session_info;

/***************************************************
 PRIVATE METHODS
 ***************************************************/

//Returns a new sessionID for the source destination session
size_t generate_unique_session_id()
{
    bool occupied[MAX_SESSION_COUNT];
    for (int i = 0; i < MAX_SESSION_COUNT; i++) {
        occupied[i] = false;
    }
    
    ll_iterator_t *iter = list_create_iterator(g_dest_session_info);
    while (list_has_next(iter))
    {
        dh_session_t *tmp = (dh_session_t *) list_get_next(iter);
        //session ids start at 1
        occupied[tmp->session_id - 1] = true;
    }
    list_destroy_iterator(iter);
    
    for (int i = 0; i < MAX_SESSION_COUNT; i++) {
        if (occupied[i] == false) {
            return i + 1; //session ids start at 1
        }
    }
    
    return 0;
}

/***************************************************
 PUBLIC METHODS
 ***************************************************/

void record_channel_module_init()
{
    g_dest_session_info = malloc(sizeof(ll_t));
    assert(g_dest_session_info != NULL);
    g_dest_session_info->head = NULL;
}

//finds an open session by its id
dh_session_t *find_session(size_t session_id)
{
    ll_iterator_t *iter = list_create_iterator(g_dest_session_info);
    while (list_has_next(iter))
    {
        dh_session_t *tmp = (dh_session_t *) list_get_next(iter);
        if (tmp->session_id == session_id) {
            return tmp;
        }
    }
    list_destroy_iterator(iter);
    return NULL; //didn't find this session id
}

//creates a session struct with a unique id
dh_session_t *open_session()
{
    size_t session_id = generate_unique_session_id();
    if (session_id == 0) { return NULL; } //can't give you a session at this time. Try later.
    
    dh_session_t *session_info = (dh_session_t *) malloc(sizeof(dh_session_t));
    assert(session_info != NULL);
    
    list_insert_value(g_dest_session_info, session_info);
    session_info->session_id = session_id;
 
    return session_info;
}

//Close an open session, and free all associated resources (inverse of open_session)
size_t close_session(dh_session_t *session_info)
{
    sgx_status_t status;
    size_t retstatus;
    
    //Ocall to ask the destination enclave to end the session
    status = end_session_ocall(&retstatus, session_info->session_id);
    if ((status != SGX_SUCCESS) || (retstatus != 0)) { return -1; }
    
    //Erase the session information for the current session
    bool deleted_successfully = list_delete_value(g_dest_session_info, session_info);
    assert(deleted_successfully);
    
    free(session_info);
    
    return 0;
}
