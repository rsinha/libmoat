#include "sgx_urts.h"
#include "interface_u.h"
#include <zmq.h>
#include <map>
#include <assert.h>

typedef struct {
    void *zmq_ctx = NULL;
    void *socket = NULL;
    sgx_measurement_t target_enclave;
} untrusted_channel_t;

std::map<uint32_t, untrusted_channel_t> channels; 

void server_setup_socket(sgx_measurement_t *target_enclave, uint32_t session_id)
{
    untrusted_channel_t channel;
    channel.zmq_ctx = zmq_ctx_new();
    channel.socket = zmq_socket(channel.zmq_ctx, ZMQ_REP);
    memcpy(&(channel.target_enclave), target_enclave, sizeof(sgx_measurement_t));

    int success = zmq_bind(channel.socket, "tcp://*:5555");
    assert(success == 0);
    printf("Server running on tcp://localhost:5555...\n");

    channels.insert(std::pair<uint32_t, untrusted_channel_t>(session_id, channel));
}

void client_setup_socket(sgx_measurement_t *target_enclave, uint32_t session_id)
{
    untrusted_channel_t channel;
    channel.zmq_ctx = zmq_ctx_new();
    channel.socket = zmq_socket(channel.zmq_ctx, ZMQ_REQ);
    memcpy(&(channel.target_enclave), target_enclave, sizeof(sgx_measurement_t));

    //ideally I should be asking some name discovery service
    int success = zmq_connect(channel.socket, "tcp://localhost:5555");
    assert(success == 0);
    printf("Client running on tcp://localhost:5555...\n");

    channels.insert(std::pair<uint32_t, untrusted_channel_t>(session_id, channel));
}

void teardown_socket(uint32_t session_id)
{
    std::map<uint32_t, untrusted_channel_t>::iterator iter = channels.find(session_id);
    if (iter != channels.end()) {
        zmq_close(iter->second.socket);
        zmq_ctx_destroy(iter->second.zmq_ctx);
    }
}

uint32_t recv_dh_msg1_ocall(sgx_measurement_t *target_enclave, sgx_dh_msg1_t* dh_msg1, uint32_t session_id)
{
    //get dh_msg1 from remote, and populate dh_msg1 struct
    //we need to communicate with a remote with right measurement,
    //though we don't verify the measurement until we get inside the enclave
    server_setup_socket(target_enclave, session_id);

    //step 3: recv dh_msg1 from the remote (client)
    std::map<uint32_t, untrusted_channel_t>::iterator iter = channels.find(session_id);
    if (iter != channels.end()) {
        zmq_recv(iter->second.socket, dh_msg1, sizeof(sgx_dh_msg1_t), 0);
        printf("Received dh_msg1...\n");
        return 0;
    }
    return 1; //ERROR
}

uint32_t send_dh_msg2_recv_dh_msg3_ocall(sgx_dh_msg2_t *dh_msg2, sgx_dh_msg3_t *dh_msg3, uint32_t session_id)
{
    std::map<uint32_t, untrusted_channel_t>::iterator iter = channels.find(session_id);
    if (iter != channels.end()) {
        //send dh_msg2 to the remote (client)
        zmq_send(iter->second.socket, dh_msg2, sizeof(sgx_dh_msg2_t), 0);
        printf("Sent dh_msg2...\n");
        //recv dh_msg3 from the remote (client)
        zmq_recv(iter->second.socket, dh_msg3, sizeof(sgx_dh_msg3_t), 0);
        printf("Received dh_msg3...\n");
        return 0;
    }
    return 1; //ERROR
}

uint32_t send_dh_msg1_recv_dh_msg2_ocall(sgx_measurement_t *target_enclave, sgx_dh_msg1_t *dh_msg1, sgx_dh_msg2_t *dh_msg2, uint32_t session_id)
{
    client_setup_socket(target_enclave, session_id);

    std::map<uint32_t, untrusted_channel_t>::iterator iter = channels.find(session_id);
    if (iter != channels.end()) {
        //send dh_msg1 to the remote (client)
         zmq_send(iter->second.socket, dh_msg1, sizeof(sgx_dh_msg1_t), 0);
         printf("Sent dh_msg1...\n");
         //recv dh_msg2 from the remote (client)
         zmq_recv(iter->second.socket, dh_msg2, sizeof(sgx_dh_msg2_t), 0);
         printf("Received dh_msg2...\n");
         return 0;
    }
    return 1; //ERROR
}

uint32_t send_dh_msg3_ocall(sgx_dh_msg3_t *dh_msg3, uint32_t session_id)
{
    //send dh_msg3 from the remote (client)
    std::map<uint32_t, untrusted_channel_t>::iterator iter = channels.find(session_id);
    if (iter != channels.end()) {
        zmq_send(iter->second.socket, dh_msg3, sizeof(sgx_dh_msg3_t), 0);
        printf("Sent dh_msg3...\n");
        return 0;
    }
    return 1;
}

uint32_t end_session_ocall(uint32_t session_id)
{
    //TODO
    //zmq_send(socket, &msg, sizeof(msg), 0);    

    teardown_socket(session_id);
    return 0;
}

/* This is a debugging ocall */
uint32_t print_debug_on_host_ocall(const char *buf)
{
    printf("%s", buf);
    return 0;
}

uint32_t send_msg_ocall(void *buf, size_t buflen, uint32_t session_id)
{
    std::map<uint32_t, untrusted_channel_t>::iterator iter = channels.find(session_id);
    if (iter != channels.end()) {
        zmq_send(iter->second.socket, buf, buflen, 0);
        printf("Sent msg...\n");
        return 0;
    }
    return 1;
}

uint32_t recv_msg_ocall(void *buf, size_t buflen, size_t *buflen_out, uint32_t session_id)
{
    std::map<uint32_t, untrusted_channel_t>::iterator iter = channels.find(session_id);
    if (iter != channels.end()) {
        *buflen_out = buflen;
        zmq_recv(iter->second.socket, buf, buflen, 0);
        printf("Received msg...\n");
        return 0;
    }
    return 1;
}

