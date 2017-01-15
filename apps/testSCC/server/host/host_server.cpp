#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX
#include <zmq.h>

#include "sgx_urts.h"
#include "host.h"
#include "interface_u.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}


int trusted(void)
{
  uint64_t pwerr;

  /* Setup enclave */
  sgx_status_t ret;
  sgx_launch_token_t token = { 0 };
     
  int token_updated = 0;

  ret = sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, &token, &token_updated, &global_eid, NULL);
  if (ret != SGX_SUCCESS)
  {
    printf("sgx_create_enclave failed: %#x\n", ret);
    return 1;
  }
  printf("created enclave...\n");
 
  ret = enclave_test(global_eid, &pwerr);
  //printf("pw_check+ took %ums\n", GetTickCount() - time);
  if (ret != SGX_SUCCESS)
  {
    printf("test failed: %#x\n", ret);
    sgx_destroy_enclave(global_eid);
    return 1;
  }

  printf("test returned %" PRIu64 "\n", pwerr);
  
  /* Destroy enclave */  
  ret = sgx_destroy_enclave(global_eid);
  if (ret != SGX_SUCCESS)
  {
    printf("sgx_destroy_enclave failed: %#x\n", ret);
    return 1;
  }
  
  return 0;
}


static void *zmq_ctx;
static void *socket;

int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    zmq_ctx = zmq_ctx_new();
    socket = zmq_socket(zmq_ctx, ZMQ_REP);
    int success = zmq_bind(socket, "tcp://*:5555");
    assert(success == 0);
    printf("Server running on tcp://localhost:5555...\n");

    int r = trusted();

    zmq_close(socket);
    zmq_ctx_destroy(zmq_ctx);

    getchar();
    return r;
}


uint32_t recv_dh_msg1_ocall(sgx_measurement_t *target_enclave, sgx_dh_msg1_t* dh_msg1, uint32_t session_id)
{
    //get dh_msg1 from remote, and populate dh_msg1 struct
    //we need to communicate with a remote with right measurement,
    //though we don't verify the measurement until we get inside the enclave

    //TODO: step 1: look up a untrusted dictionary of socket to enclave measurement mappings i.e. a discovery service

    //TODO: step 2: bind socket to session_id

    //step 3: recv dh_msg1 from the remote (client)
    zmq_recv(socket, dh_msg1, sizeof(sgx_dh_msg1_t), 0);
    printf("Received dh_msg1...\n");
    return 0;
}

uint32_t send_dh_msg2_recv_dh_msg3_ocall(sgx_dh_msg2_t *dh_msg2, sgx_dh_msg3_t *dh_msg3, uint32_t session_id)
{
    //TODO: step 1: look up socket by session_id

    //send dh_msg2 to the remote (client)
    zmq_send(socket, dh_msg2, sizeof(sgx_dh_msg2_t), 0);
    printf("Sent dh_msg2...\n");
    
    //recv dh_msg3 from the remote (client)
    zmq_recv(socket, dh_msg3, sizeof(sgx_dh_msg3_t), 0);
    printf("Received dh_msg3...\n");

    return 0;
}

uint32_t send_dh_msg1_recv_dh_msg2_ocall(sgx_dh_msg1_t *dh_msg1, sgx_dh_msg2_t *dh_msg2, uint32_t session_id)
{
    //TODO: step 1: look up socket by session_id

    //send dh_msg1 to the remote (client)
    zmq_send(socket, dh_msg1, sizeof(sgx_dh_msg1_t), 0);
    printf("Sent dh_msg1...\n");
    
    //recv dh_msg2 from the remote (client)
    zmq_recv(socket, dh_msg2, sizeof(sgx_dh_msg2_t), 0);
    printf("Received dh_msg2...\n");

    return 0;
}

uint32_t send_dh_msg3_ocall(sgx_dh_msg3_t *dh_msg3, uint32_t session_id)
{
    //TODO: step 1: look up socket by session_id

    //send dh_msg3 from the remote (client)
    zmq_send(socket, dh_msg3, sizeof(sgx_dh_msg3_t), 0);
    printf("Sent dh_msg3...\n");

    return 0;
}

uint32_t end_session_ocall(uint32_t session_id)
{
    //TODO
    //zmq_send(socket, &msg, sizeof(msg), 0);    
    return 0;
}

/* This is a debugging ocall */
void print_debug_on_host_ocall(const char *buf)
{
  printf("DEBUG: %s\n", buf);
}

void send_msg_ocall(void *buf, size_t buflen)
{
    zmq_send(socket, buf, buflen, 0);
    printf("Sent msg...\n");
}

void recv_msg_ocall(void *buf, size_t buflen, size_t *buflen_out)
{
    *buflen_out = buflen;
    zmq_recv(socket, buf, buflen, 0);
    printf("Received msg...\n");
}

void print_hex(uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        if (i > 0) printf(":");
        printf("%02X", buf[i]);
    }
}
