#include "sgx_urts.h"
#include "sgx_dh.h"
//#include "interface_u.h"
#include <zmq.h>
#include "BackendDBInterface.hpp"
#include "RocksDBInterface.hpp"

#include <map>
#include <iostream>
#include <fstream>
#include <assert.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <cstdlib>
#include "json.hpp"

using json = nlohmann::json;

/* Internal Definitions */

#define STORAGE_KVS_ROOT "/tmp/barbican/kvs/"
#define STORAGE_FS_ROOT "/tmp/barbican/fs/"

typedef struct {
    void *zmq_ctx_outbound = NULL;    //zmq ctx of connection for sending msg
    void *zmq_skt_outbound = NULL;    //zmq socket of connection for sending msg
    void *zmq_ctx_inbound = NULL;     //zmq ctx of connection for receiving msg
    void *zmq_skt_inbound = NULL;     //zmq socket of connection for receiving msg
    sgx_measurement_t target_enclave; //measurement of remote enclave
    char *remote_name = NULL;
} untrusted_channel_t;

typedef struct _merkle_node {
    sgx_sha256_hash_t    hash;
    struct _merkle_node *left_child;
    struct _merkle_node *right_child;
    struct _merkle_node *parent;
} merkle_node_t;

/* Global Internal State */
std::map<int64_t, untrusted_channel_t>  g_channels; //map session id to channel struct
merkle_node_t                          *g_merkle_root;
merkle_node_t                         **g_merkle_leaves;
size_t                                  g_in_order_traversal_counter;
BackendDBInterface                     *g_db_context;
void                                   *g_prev_reply;
std::map<std::string, std::string>      g_config_kvs_inputs;
std::map<std::string, std::string>      g_config_kvs_outputs;
std::string                             g_config_scc_self;
std::map<std::string, std::string>      g_config_scc_actors; //map remote entity name to ip address
std::map<std::string, bool>             g_config_scc_roles; //map remote entity name to role (client / server)

void teardown_channel(int64_t session_id)
{
    std::map<int64_t, untrusted_channel_t>::iterator iter = g_channels.find(session_id);
    if (iter != g_channels.end()) {
        zmq_close(iter->second.zmq_skt_outbound);
        zmq_ctx_destroy(iter->second.zmq_ctx_outbound);
        zmq_close(iter->second.zmq_skt_inbound);
        zmq_ctx_destroy(iter->second.zmq_ctx_inbound);
        g_channels.erase(iter);
    }
}

extern "C" size_t start_session_ocall(const char *name, sgx_measurement_t *target_enclave, int64_t session_id, size_t *is_server)
{
    untrusted_channel_t channel;
    memcpy(&(channel.target_enclave), target_enclave, sizeof(sgx_measurement_t));

    channel.remote_name = (char *) malloc(strlen(name) + 1);
    assert(channel.remote_name != NULL);
    memcpy(channel.remote_name, name, strlen(name) + 1);

    std::string actor_name(name);
    std::map<std::string, bool>::iterator role_iter = g_config_scc_roles.find(actor_name);
    if (role_iter == g_config_scc_roles.end()) { return -1; }
    *is_server = (role_iter->second) ? 1 : 0;

    std::map<std::string, std::string>::iterator iter = g_config_scc_actors.find(actor_name);
    if (iter == g_config_scc_actors.end()) { return -1; }
    std::string self_addr = "tcp://*:" + g_config_scc_self;
    std::string remote_addr = iter->second;

    std::cout << "within " << (*is_server ? "server" : "client") << std::endl;

    if (*is_server) {
        channel.zmq_ctx_outbound = zmq_ctx_new();
        channel.zmq_skt_outbound = zmq_socket(channel.zmq_ctx_outbound, ZMQ_PUSH);
        assert(zmq_bind(channel.zmq_skt_outbound, self_addr.c_str()) == 0);
        channel.zmq_ctx_inbound = zmq_ctx_new();
        channel.zmq_skt_inbound = zmq_socket(channel.zmq_ctx_inbound, ZMQ_PULL);
        assert(zmq_connect(channel.zmq_skt_inbound, remote_addr.c_str()) == 0);
    } else {
        channel.zmq_ctx_inbound = zmq_ctx_new();
        channel.zmq_skt_inbound = zmq_socket(channel.zmq_ctx_inbound, ZMQ_PULL);
        assert(zmq_connect(channel.zmq_skt_inbound, remote_addr.c_str()) == 0);
        channel.zmq_ctx_outbound = zmq_ctx_new();
        channel.zmq_skt_outbound = zmq_socket(channel.zmq_ctx_outbound, ZMQ_PUSH);
        assert(zmq_bind(channel.zmq_skt_outbound, self_addr.c_str()) == 0);
    }

    std::cout << "self running at " << self_addr << std::endl;
    std::cout << "Connected to " << name << " running on " << remote_addr << std::endl;

    g_channels.insert(std::pair<int64_t, untrusted_channel_t>(session_id, channel));
    return 0;
}

extern "C" size_t recv_dh_msg1_ocall(sgx_measurement_t *target_enclave, sgx_dh_msg1_t* dh_msg1, int64_t session_id)
{
    //get dh_msg1 from remote, and populate dh_msg1 struct
    //we need to communicate with a remote with right measurement,
    //though we don't verify the measurement until we get inside the enclave
    //server_setup_socket(target_enclave, session_id);

    //step 3: recv dh_msg1 from the remote (client)
    std::map<int64_t, untrusted_channel_t>::iterator iter = g_channels.find(session_id);
    if (iter != g_channels.end()) {
        zmq_recv(iter->second.zmq_skt_inbound, dh_msg1, sizeof(sgx_dh_msg1_t), 0);
        std::cout << "Received dh_msg1...\n";
        return 0;
    }
    return 1; //ERROR
}

extern "C" size_t send_dh_msg2_recv_dh_msg3_ocall(sgx_dh_msg2_t *dh_msg2, sgx_dh_msg3_t *dh_msg3, int64_t session_id)
{
    std::map<int64_t, untrusted_channel_t>::iterator iter = g_channels.find(session_id);
    if (iter != g_channels.end()) {
        //send dh_msg2 to the remote (client)
        zmq_send(iter->second.zmq_skt_outbound, dh_msg2, sizeof(sgx_dh_msg2_t), 0);
        std::cout << "Sent dh_msg2...\n";
        //recv dh_msg3 from the remote (client)
        zmq_recv(iter->second.zmq_skt_inbound, dh_msg3, sizeof(sgx_dh_msg3_t), 0);
        std::cout << "Received dh_msg3...\n";
        return 0;
    }
    return 1; //ERROR
}

extern "C" size_t send_dh_msg1_recv_dh_msg2_ocall(sgx_measurement_t *target_enclave, sgx_dh_msg1_t *dh_msg1, sgx_dh_msg2_t *dh_msg2, int64_t session_id)
{
    //client_setup_socket(target_enclave, session_id);

    std::map<int64_t, untrusted_channel_t>::iterator iter = g_channels.find(session_id);
    if (iter != g_channels.end()) {
        //send dh_msg1 to the remote (client)
         zmq_send(iter->second.zmq_skt_outbound, dh_msg1, sizeof(sgx_dh_msg1_t), 0);
         std::cout << "Sent dh_msg1...\n";
         //recv dh_msg2 from the remote (client)
         zmq_recv(iter->second.zmq_skt_inbound, dh_msg2, sizeof(sgx_dh_msg2_t), 0);
         std::cout << "Received dh_msg2...\n";
         return 0;
    }
    return 1; //ERROR
}

extern "C" size_t send_dh_msg3_ocall(sgx_dh_msg3_t *dh_msg3, int64_t session_id)
{
    //send dh_msg3 from the remote (client)
    std::map<int64_t, untrusted_channel_t>::iterator iter = g_channels.find(session_id);
    if (iter != g_channels.end()) {
        zmq_send(iter->second.zmq_skt_outbound, dh_msg3, sizeof(sgx_dh_msg3_t), 0);
        std::cout << "Sent dh_msg3...\n";
        return 0;
    }
    return 1;
}

extern "C" size_t end_session_ocall(int64_t session_id)
{
    //TODO: zmq_send(zmq_skt_outbound, &msg, sizeof(msg), 0);

    teardown_channel(session_id);
    return 0;
}

/* This is a debugging ocall */
extern "C" size_t print_debug_on_host_ocall(const char *buf)
{
    printf("%s", buf);
    return 0;
}

extern "C" size_t send_msg_ocall(void *buf, size_t len, int64_t session_id)
{
    std::map<int64_t, untrusted_channel_t>::iterator iter = g_channels.find(session_id);
    if (iter != g_channels.end()) {
        zmq_send(iter->second.zmq_skt_outbound, (uint8_t *) buf, len, 0);
        printf("Sent %zu bytes in session %zu\n", len, session_id);
        return 0;
    }
    return -1;
}

extern "C" size_t recv_msg_ocall(void *buf, size_t len, int64_t session_id)
{
    std::map<int64_t, untrusted_channel_t>::iterator iter = g_channels.find(session_id);
    if (iter != g_channels.end()) {
        zmq_recv(iter->second.zmq_skt_inbound, buf, len, 0);
        printf("Received %zu bytes in session %zu\n", len, session_id);
        return 0;
    }
    return -1;
}

extern "C" size_t fs_init_service_ocall(size_t num_blocks)
{
    std::string command("");
    command = (command + "mkdir -p ") + STORAGE_FS_ROOT;

    std::cout << "invoking " << command << std::endl;
    const int dir_err = system(command.c_str());
    if (-1 == dir_err)
    {
        std::cout << "Error creating directory " << STORAGE_FS_ROOT << std::endl;
        exit(1);
    }

    return 0;
}

extern "C" size_t fs_write_block_ocall(size_t addr, void *buf, size_t len)
{
    std::ofstream fout;

    std::string prefix = STORAGE_FS_ROOT;
    std::string filename = prefix + std::to_string(addr);

    fout.open(filename.c_str(), std::ios::binary | std::ios::out);
    fout.write((char *) buf, (std::streamsize) len);
    printf("Wrote %zu bytes to %s\n", len, filename.c_str());

    fout.close();
    return 0;
}

extern "C" size_t fs_read_block_ocall(size_t addr, void *buf, size_t len)
{
    std::ifstream fin;

    std::string prefix = STORAGE_FS_ROOT;
    std::string filename = prefix + std::to_string(addr);

    fin.open(filename, std::ios::binary | std::ios::in);
    fin.read((char *) buf, (std::streamsize) len);
    printf("Read %zu bytes from %s\n", len, filename.c_str());

    fin.close();
    return 0;
}

extern "C" size_t fs_delete_block_ocall(size_t addr)
{
    std::string prefix = STORAGE_FS_ROOT;
    std::string filename = prefix + std::to_string(addr);
    std::string command = "rm " + filename;

    std::cout << "invoking " << command << std::endl;

    const int dir_err = system(command.c_str());
    if (-1 == dir_err)
    {
        std::cout << "Error removing file " << filename << std::endl;
        exit(1);
    }
    return 0;
}

/*
 INPUT node: current node in the recursion
 INPUT depth: current depth in the recursion
 INPUT buf: hashes emited by the enclave
 INPUT max_depth: max depth of the merkle tree
 */
size_t create_merkle_tree_helper(merkle_node_t *node, size_t depth, sgx_sha256_hash_t *buf, size_t max_depth)
{
    //populate the hash
    //enclave sends us hashes ordered from leaf to root, hence [max_depth - depth]
    memcpy(&(node->hash), &(buf[max_depth - depth]), sizeof(sgx_sha256_hash_t));

    //Terminate recursion if we hit max_depth
    if (depth == max_depth) {
        node->left_child = NULL;
        node->right_child = NULL;
        g_merkle_leaves[g_in_order_traversal_counter] = node;
        g_in_order_traversal_counter++;
        return 0;
    }

    //create the children, and recurse.
    node->left_child = (merkle_node_t *) malloc(sizeof(merkle_node_t));
    if (node->left_child == NULL) { return -1; }
    node->right_child = (merkle_node_t *) malloc(sizeof(merkle_node_t));
    if (node->right_child == NULL) { return -1; }

    node->left_child->parent = node;
    node->right_child->parent = node;

    size_t r1 = create_merkle_tree_helper(node->left_child, depth + 1, buf, max_depth);
    size_t r2 = create_merkle_tree_helper(node->right_child, depth + 1, buf, max_depth);

    return r1 == 0 && r2 == 0 ? 0 : -1;
}

extern "C" size_t create_merkle_ocall(sgx_sha256_hash_t *buf, size_t num_hashes, size_t num_blocks)
{
    g_merkle_root = (merkle_node_t *) malloc(sizeof(merkle_node_t));
    if (g_merkle_root == NULL) { return -1; }

    g_merkle_leaves = (merkle_node_t **) malloc(sizeof(merkle_node_t *) * num_blocks);
    if (g_merkle_leaves == NULL) { return -1; }
    g_in_order_traversal_counter = 0;

    g_merkle_root->parent = NULL;
    size_t r = create_merkle_tree_helper(g_merkle_root, 0, buf, num_hashes - 1);
    assert(g_in_order_traversal_counter == num_blocks);

    return r;
}

extern "C" size_t read_merkle_ocall(size_t addr, sgx_sha256_hash_t *buf, size_t num_hashes)
{
    merkle_node_t *node = g_merkle_leaves[addr - 1]; //addresses start at 1
    size_t height = 0;
    while (height < num_hashes)
    {
        merkle_node_t *sibling = node->parent->left_child == node ?
            node->parent->right_child : node->parent->left_child;
        memcpy(&(buf[height]), &(sibling->hash), sizeof(sgx_sha256_hash_t));
        node = node->parent;
        height += 1;
    }
    return 0;
}

extern "C" size_t write_merkle_ocall(size_t addr, sgx_sha256_hash_t *buf, size_t num_hashes)
{
    merkle_node_t *node = g_merkle_leaves[addr - 1]; //addresses start at 1
    size_t height = 0;
    while (height < num_hashes)
    {
        memcpy(&(node->hash), &(buf[height]), sizeof(sgx_sha256_hash_t));
        node = node->parent;
        height += 1;
    }
    return 0;
}

extern "C" size_t kvs_init_service_ocall()
{
    g_db_context = new RocksDBInterface();
    g_db_context->backend_db_connect_server();
    g_prev_reply = NULL;

    std::string command("");
    command = (command + "mkdir -p ") + STORAGE_KVS_ROOT;

    std::cout << "invoking " << command << std::endl;
    const int dir_err = system(command.c_str());
    if (-1 == dir_err)
    {
        std::cout << "Error creating directory " << STORAGE_KVS_ROOT << std::endl;
        exit(1);
    }

    return 0;
}

extern "C" size_t kvs_create_ocall(int64_t fd, const char *name)
{
    std::string db_path(name);
    db_path = STORAGE_KVS_ROOT + db_path;

    std::cout << "creating " << db_path << std::endl;

    bool success = g_db_context->backend_db_create(fd, db_path.c_str());
    return success ? 0 : -1;
}

extern "C" size_t kvs_destroy_ocall(int64_t fd, const char *name)
{
    bool success = g_db_context->backend_db_destroy(fd, name);
    return success ? 0 : -1;
}

extern "C" size_t kvs_save_ocall(int64_t fd, const char *name)
{
    std::string db_path(name);

    std::map<std::string, std::string>::iterator iter = g_config_kvs_outputs.find(db_path);
    if (iter == g_config_kvs_outputs.end()) { return -1; }

    std::cout << "saving " << db_path << " to " << iter->second << std::endl;

    std::string db_backup_path = STORAGE_KVS_ROOT + iter->second;
    bool success = g_db_context->backend_db_save(fd, db_backup_path.c_str());
    return success ? 0 : -1;
}

extern "C" size_t kvs_load_ocall(int64_t fd, const char *name)
{
    std::string db_path(name);
    std::map<std::string, std::string>::iterator iter = g_config_kvs_inputs.find(db_path);
    if (iter == g_config_kvs_inputs.end()) { return -1; }

    std::cout << "loading " << db_path << " from " << iter->second << std::endl;

    db_path = STORAGE_KVS_ROOT + db_path;
    std::string db_backup_path = STORAGE_KVS_ROOT + iter->second;
    bool success = g_db_context->backend_db_load(fd, db_path.c_str(), db_backup_path.c_str());
    return success ? 0 : -1;
}

extern "C" size_t kvs_set_ocall(int64_t fd, void *k, size_t k_len, void *buf, size_t buf_len)
{
    bool success = g_db_context->backend_db_put(fd, (uint8_t *) k, k_len, (uint8_t *) buf, buf_len);
    return success ? 0 : -1;
}

extern "C" size_t kvs_get_ocall(int64_t fd, void *k, size_t k_len, void **untrusted_buf)
{
    if (g_prev_reply != NULL) {
        bool success = g_db_context->backend_db_free(g_prev_reply);
        if (!success) { return -1; }
        g_prev_reply = NULL;
    }

    uint8_t *v; size_t v_len;
    bool success = g_db_context->backend_db_get(fd, (uint8_t *) k, k_len, &v, &v_len);
    if (!success) { return -1; }
    *untrusted_buf = v;
    g_prev_reply = v;
    return 0;
}

extern "C" size_t kvs_delete_ocall(int64_t fd, void *k, size_t k_len)
{
    bool success = g_db_context->backend_db_delete(fd, (uint8_t *) k, k_len);
    return success ? 0 : -1;
}

extern "C" size_t kvs_close_ocall(int64_t fd)
{
    bool success = g_db_context->backend_db_close(fd);
    return success ? 0 : -1;
}

extern "C" size_t malloc_ocall(size_t num_bytes, void **untrusted_buf)
{
    *untrusted_buf = malloc(num_bytes);
    return untrusted_buf != NULL ? 0 : -1;
}

extern "C" size_t free_ocall(void *untrusted_buf)
{
    free(untrusted_buf);
    return 0;
}

void register_kvs_input(const std::string &name, const std::string &backup_path)
{
    g_config_kvs_inputs.insert(std::pair<std::string, std::string>(name, backup_path));
    std::cout << "Noting that input db " << name << " is backed up at " << backup_path << std::endl;
}

void register_kvs_output(const std::string &name, const std::string &backup_path)
{
    g_config_kvs_outputs.insert(std::pair<std::string, std::string>(name, backup_path));
    std::cout << "Noting that output db " << name << " is backed up at " << backup_path << std::endl;
}

void register_scc_actor(const std::string &name, const std::string &ip_addr, bool role_is_server)
{
    g_config_scc_actors.insert(std::pair<std::string, std::string>(name, ip_addr));
    g_config_scc_roles.insert(std::pair<std::string, bool>(name, role_is_server));
    std::cout << "Noting that remote actor " << name << " can be reached at " << ip_addr << 
        ", we will act as " << (role_is_server ? "server" : "client") << std::endl;
}

void init_barbican(const std::string &json_str)
{
    try {
        json j = json::parse(json_str);

        json inputs = j["kvs_inputs"];
        std::cout << "Reading input config ..." << std::endl;
        for (json::iterator it = inputs.begin(); it != inputs.end(); ++it) {
            register_kvs_input(it.key(), it.value().get<std::string>());
        }

        json outputs = j["kvs_outputs"];
        std::cout << "Reading output config ..." << std::endl;
        for (json::iterator it = outputs.begin(); it != outputs.end(); ++it) {
            register_kvs_output(it.key(), it.value().get<std::string>());
        }

        json self_addr = j["scc_self"];
        g_config_scc_self = self_addr.get<std::string>();

        json actors = j["scc_actors"];
        std::cout << "Reading network config ..." << std::endl;
        for (json::iterator it = actors.begin(); it != actors.end(); ++it) {
            json actor_info = actors[it.key()];
            json ip_addr = actor_info["url"];
            json role = actor_info["role_server"];
            register_scc_actor(it.key(), ip_addr.get<std::string>(), role.get<bool>());
        }

    } catch (const std::exception& ex) {
        std::cout << "Error parsing json config: " << ex.what() << std::endl;
        exit(1);
    }
}