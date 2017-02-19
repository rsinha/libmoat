#include "sgx_urts.h"
#include "interface_u.h"
#include <zmq.h>
#include <map>
#include <iostream>
#include <fstream>
#include <assert.h>

typedef struct
{
    size_t type;
    size_t length;
} libmoat_ciphertext_header_t;

typedef struct {
    void *zmq_ctx_outbound = NULL;    //zmq ctx of connection for sending msg
    void *zmq_skt_outbound = NULL;    //zmq socket of connection for sending msg
    void *zmq_ctx_inbound = NULL;    //zmq ctx of connection for receiving msg
    void *zmq_skt_inbound = NULL;    //zmq socket of connection for receiving msg
    sgx_measurement_t target_enclave; //measurement of remote enclave
} untrusted_channel_t;

std::map<size_t, untrusted_channel_t> channels;

void server_setup_socket(sgx_measurement_t *target_enclave, size_t session_id)
{
    //ideally I should be asking some name discovery service
    untrusted_channel_t channel;
    memcpy(&(channel.target_enclave), target_enclave, sizeof(sgx_measurement_t));

    channel.zmq_ctx_outbound = zmq_ctx_new();
    channel.zmq_skt_outbound = zmq_socket(channel.zmq_ctx_outbound, ZMQ_PUSH);
    assert(zmq_bind(channel.zmq_skt_outbound, "tcp://*:5555") == 0);
    printf("server running on tcp://localhost:5555...\n");

    channel.zmq_ctx_inbound = zmq_ctx_new();
    channel.zmq_skt_inbound = zmq_socket(channel.zmq_ctx_inbound, ZMQ_PULL);
    assert(zmq_connect(channel.zmq_skt_inbound, "tcp://localhost:5556") == 0);
    printf("Connected to client running on tcp://localhost:5556...\n");

    channels.insert(std::pair<size_t, untrusted_channel_t>(session_id, channel));
}

void client_setup_socket(sgx_measurement_t *target_enclave, size_t session_id)
{
    //ideally I should be asking some name discovery service
    untrusted_channel_t channel;
    memcpy(&(channel.target_enclave), target_enclave, sizeof(sgx_measurement_t));

    channel.zmq_ctx_inbound = zmq_ctx_new();
    channel.zmq_skt_inbound = zmq_socket(channel.zmq_ctx_inbound, ZMQ_PULL);
    assert(zmq_connect(channel.zmq_skt_inbound, "tcp://localhost:5555") == 0);
    printf("Connected to server running on tcp://localhost:5555...\n");

    channel.zmq_ctx_outbound = zmq_ctx_new();
    channel.zmq_skt_outbound = zmq_socket(channel.zmq_ctx_outbound, ZMQ_PUSH);
    assert(zmq_bind(channel.zmq_skt_outbound, "tcp://*:5556") == 0);
    printf("client running on tcp://localhost:5556...\n");


    channels.insert(std::pair<size_t, untrusted_channel_t>(session_id, channel));
}

void teardown_channel(size_t session_id)
{
    std::map<size_t, untrusted_channel_t>::iterator iter = channels.find(session_id);
    if (iter != channels.end()) {
        zmq_close(iter->second.zmq_skt_outbound);
        zmq_ctx_destroy(iter->second.zmq_ctx_outbound);
        zmq_close(iter->second.zmq_skt_inbound);
        zmq_ctx_destroy(iter->second.zmq_ctx_inbound);
	channels.erase(iter);
    }
}

size_t recv_dh_msg1_ocall(sgx_measurement_t *target_enclave, sgx_dh_msg1_t* dh_msg1, size_t session_id)
{
    //get dh_msg1 from remote, and populate dh_msg1 struct
    //we need to communicate with a remote with right measurement,
    //though we don't verify the measurement until we get inside the enclave
    server_setup_socket(target_enclave, session_id);

    //step 3: recv dh_msg1 from the remote (client)
    std::map<size_t, untrusted_channel_t>::iterator iter = channels.find(session_id);
    if (iter != channels.end()) {
        zmq_recv(iter->second.zmq_skt_inbound, dh_msg1, sizeof(sgx_dh_msg1_t), 0);
        printf("Received dh_msg1...\n");
        return 0;
    }
    return 1; //ERROR
}

size_t send_dh_msg2_recv_dh_msg3_ocall(sgx_dh_msg2_t *dh_msg2, sgx_dh_msg3_t *dh_msg3, size_t session_id)
{
    std::map<size_t, untrusted_channel_t>::iterator iter = channels.find(session_id);
    if (iter != channels.end()) {
        //send dh_msg2 to the remote (client)
        zmq_send(iter->second.zmq_skt_outbound, dh_msg2, sizeof(sgx_dh_msg2_t), 0);
        printf("Sent dh_msg2...\n");
        //recv dh_msg3 from the remote (client)
        zmq_recv(iter->second.zmq_skt_inbound, dh_msg3, sizeof(sgx_dh_msg3_t), 0);
        printf("Received dh_msg3...\n");
        return 0;
    }
    return 1; //ERROR
}

size_t send_dh_msg1_recv_dh_msg2_ocall(sgx_measurement_t *target_enclave, sgx_dh_msg1_t *dh_msg1, sgx_dh_msg2_t *dh_msg2, size_t session_id)
{
    client_setup_socket(target_enclave, session_id);

    std::map<size_t, untrusted_channel_t>::iterator iter = channels.find(session_id);
    if (iter != channels.end()) {
        //send dh_msg1 to the remote (client)
         zmq_send(iter->second.zmq_skt_outbound, dh_msg1, sizeof(sgx_dh_msg1_t), 0);
         printf("Sent dh_msg1...\n");
         //recv dh_msg2 from the remote (client)
         zmq_recv(iter->second.zmq_skt_inbound, dh_msg2, sizeof(sgx_dh_msg2_t), 0);
         printf("Received dh_msg2...\n");
         return 0;
    }
    return 1; //ERROR
}

size_t send_dh_msg3_ocall(sgx_dh_msg3_t *dh_msg3, size_t session_id)
{
    //send dh_msg3 from the remote (client)
    std::map<size_t, untrusted_channel_t>::iterator iter = channels.find(session_id);
    if (iter != channels.end()) {
        zmq_send(iter->second.zmq_skt_outbound, dh_msg3, sizeof(sgx_dh_msg3_t), 0);
        printf("Sent dh_msg3...\n");
        return 0;
    }
    return 1;
}

size_t end_session_ocall(size_t session_id)
{
    //TODO: zmq_send(zmq_skt_outbound, &msg, sizeof(msg), 0);

    teardown_channel(session_id);
    return 0;
}

/* This is a debugging ocall */
size_t print_debug_on_host_ocall(const char *buf)
{
    printf("%s", buf);
    return 0;
}

size_t send_msg_ocall(void *buf, size_t len, size_t session_id)
{
    std::map<size_t, untrusted_channel_t>::iterator iter = channels.find(session_id);
    if (iter != channels.end()) {
        zmq_send(iter->second.zmq_skt_outbound, (uint8_t *) buf, sizeof(libmoat_ciphertext_header_t), 0);
        zmq_send(iter->second.zmq_skt_outbound, ((uint8_t *) buf) + sizeof(libmoat_ciphertext_header_t), len - sizeof(libmoat_ciphertext_header_t), 0);
        printf("Sent msg...\n");
        return 0;
    }
    return 1;
}

size_t recv_msg_ocall(void *buf, size_t len, size_t session_id)
{
    std::map<size_t, untrusted_channel_t>::iterator iter = channels.find(session_id);
    if (iter != channels.end()) {
        zmq_recv(iter->second.zmq_skt_inbound, buf, len, 0);
        printf("Received msg...\n");
        return 0;
    }
    return 1;
}

size_t write_block_ocall(void *buf, size_t len, size_t addr)
{
    std::ofstream fout;

    std::string prefix = "/tmp/libmoat";
    std::string filename = prefix + std::to_string(addr);

    fout.open(filename.c_str(), std::ios::binary | std::ios::out);

    fout.write((char *) buf, (std::streamsize) len);
    fout.close();
    return 0;
}

size_t read_block_ocall(void *buf, size_t len, size_t addr)
{
    std::ifstream fin;

    std::string prefix = "/tmp/libmoat";
    std::string filename = prefix + std::to_string(addr);

    fin.open(filename, std::ios::binary | std::ios::in);

    fin.read((char *) buf, (std::streamsize) len);
    fin.close();
    return 0;
}
