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
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <cstdlib>
#include <time.h>
#include <boost/date_time/posix_time/posix_time.hpp>
#include "json.hpp"

//#include "Ledger.pb.h"
#include "LedgerClient.h"

using json = nlohmann::json;

/* Internal Definitions */

#define STORAGE_FS_ROOT (g_scratch_space_root + "/fs/")
#define STORAGE_KVS_ROOT (g_scratch_space_root + "/kvs/")

#define LEDGER_URL "localhost:8080"
#define CHAINCODE_NAME  "luciditee"

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

typedef std::pair<std::string, std::string> strpair_t;

static LedgerClient *client = NULL;





/* Global Internal State */
std::map<int64_t, untrusted_channel_t>  g_channels; //map session id to channel struct
merkle_node_t                          *g_merkle_root;
merkle_node_t                         **g_merkle_leaves;
size_t                                  g_in_order_traversal_counter;
BackendDBInterface                     *g_db_context;
void                                   *g_prev_reply;
std::map<std::string, std::string>      g_config_kvs_inputs;
std::map<std::string, std::string>      g_config_kvs_outputs;
std::map<std::string, strpair_t>        g_config_kvs_state;
std::map<std::string, std::string>      g_config_fs_outputs;
std::map<std::string, std::string>      g_config_fs_inputs;
std::map<std::string, strpair_t>        g_config_fs_state;
std::string                             g_config_ledger;
std::string                             g_config_scc_self;
std::map<std::string, std::string>      g_config_scc_actors; //map remote entity name to ip address
std::map<std::string, bool>             g_config_scc_roles; //map remote entity name to role (client / server)
std::map<int64_t, std::string>          g_file_paths;

std::string                             g_scratch_space_root;

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

    std::cout << "barbican: within " << (*is_server ? "server" : "client") << std::endl;

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

    std::cout << "barbican: self running at " << self_addr << std::endl;
    std::cout << "barbican: Connected to " << name << " running on " << remote_addr << std::endl;

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
        std::cout << "barbican: Received dh_msg1...\n";
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
        std::cout << "barbican: Sent dh_msg2...\n";
        //recv dh_msg3 from the remote (client)
        zmq_recv(iter->second.zmq_skt_inbound, dh_msg3, sizeof(sgx_dh_msg3_t), 0);
        std::cout << "barbican: Received dh_msg3...\n";
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
         std::cout << "barbican: Sent dh_msg1...\n";
         //recv dh_msg2 from the remote (client)
         zmq_recv(iter->second.zmq_skt_inbound, dh_msg2, sizeof(sgx_dh_msg2_t), 0);
         std::cout << "barbican: Received dh_msg2...\n";
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
        std::cout << "barbican: Sent dh_msg3...\n";
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

const std::string currentDateTime() {
    time_t     now = time(0);
    struct tm  tstruct;
    char       buf[80];
    tstruct = *localtime(&now);
    // Visit http://en.cppreference.com/w/cpp/chrono/c/strftime
    // for more information about date/time format
    strftime(buf, sizeof(buf), "%Y-%m-%d.%X", &tstruct);

    return buf;
} 

extern "C" size_t sleep_ocall(uint32_t microseconds)
{
    usleep(microseconds);
}

extern "C" size_t print_time_of_day_ocall()
{
    //std::time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    //std::cout << "####### current time: " << std::ctime(&t);
    boost::posix_time::ptime date_time = boost::posix_time::microsec_clock::universal_time();
    std::cout << "##### current time: " << date_time << std::endl;
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
        printf("barbican: Sent %zu bytes in session %zu\n", len, session_id);
        return 0;
    }
    return -1;
}

extern "C" size_t recv_msg_ocall(void *buf, size_t len, int64_t session_id)
{
    std::map<int64_t, untrusted_channel_t>::iterator iter = g_channels.find(session_id);
    if (iter != g_channels.end()) {
        zmq_recv(iter->second.zmq_skt_inbound, buf, len, 0);
        printf("barbican: Received %zu bytes in session %zu\n", len, session_id);
        return 0;
    }
    return -1;
}

extern "C" size_t fs_init_service_ocall()
{
    std::string command(""); 
    command = command + "rm -rf " + STORAGE_FS_ROOT + "*";
    std::cout << "barbican: invoking " << command << std::endl;
    int dir_err = system(command.c_str());
    if (-1 == dir_err)
    {
        std::cout << "barbican: Error removing contents of directory " << STORAGE_FS_ROOT << std::endl;
        exit(1);
    }
    
    command = "";
    command = command + "mkdir -p " + STORAGE_FS_ROOT;
    std::cout << "barbican: invoking " << command << std::endl;
    dir_err = system(command.c_str());
    if (-1 == dir_err)
    {
        std::cout << "barbican: Error creating directory " << STORAGE_FS_ROOT << std::endl;
        exit(1);
    }

    return 0;
}

extern "C" size_t fs_create_ocall(int64_t fd, const char *name)
{
    std::string path(name);
    path = STORAGE_FS_ROOT + path;
    std::cout << "barbican: creating " << path << std::endl;
    std::string command = "mkdir -p " + path;
    std::cout << "barbican: invoking " << command << std::endl;
    const int dir_err = system(command.c_str());
    if (-1 == dir_err)
    {
        std::cout << "barbican: Error creating directory " << path << std::endl;
        exit(1);
    }

    std::map<int64_t, std::string>::iterator iter = g_file_paths.find(fd);
    assert(iter == g_file_paths.end()); //fd shouldn't already exist
    g_file_paths.insert(std::pair<int64_t, std::string>(fd, path));

    return 0;
}

extern "C" size_t fs_destroy_ocall(int64_t fd, const char *name)
{
    std::map<int64_t, std::string>::iterator iter = g_file_paths.find(fd);
    if (iter == g_file_paths.end()) { return -1; }

    std::string command = "rm -rf " + iter->second;
    std::cout << "barbican: invoking " << command << std::endl;

    const int dir_err = system(command.c_str());
    if (-1 == dir_err)
    {
        std::cout << "Error removing file " << iter->second << std::endl;
        exit(1);
    }

    g_file_paths.erase(iter);
    return 0;
}

extern "C" size_t fs_write_block_ocall(int64_t fd, size_t addr, void *buf, size_t len)
{
    std::map<int64_t, std::string>::iterator iter = g_file_paths.find(fd);
    if (iter == g_file_paths.end()) { return -1; }
    std::string filename = iter->second + "/" + std::to_string(addr);

    std::ofstream fout;
    fout.open(filename.c_str(), std::ios::binary | std::ios::out);
    fout.write((char *) buf, (std::streamsize) len);
    printf("barbican: Wrote %zu bytes to %s\n", len, filename.c_str());

    fout.close();
    return 0;
}

extern "C" size_t fs_read_block_ocall(int64_t fd, size_t addr, void *buf, size_t len)
{
    std::map<int64_t, std::string>::iterator iter = g_file_paths.find(fd);
    if (iter == g_file_paths.end()) { return -1; }
    std::string filename = iter->second + "/" + std::to_string(addr);

    std::ifstream fin;
    fin.open(filename, std::ios::binary | std::ios::in);
    fin.read((char *) buf, (std::streamsize) len);
    printf("barbican: Read %zu bytes from %s\n", len, filename.c_str());

    fin.close();
    return 0;
}

extern "C" size_t fs_delete_block_ocall(int64_t fd, size_t addr)
{
    std::map<int64_t, std::string>::iterator iter = g_file_paths.find(fd);
    if (iter == g_file_paths.end()) { return -1; }
    std::string filename = iter->second + "/" + std::to_string(addr);

    std::string command = "rm " + filename;
    std::cout << "barbican: invoking " << command << std::endl;

    const int dir_err = system(command.c_str());
    if (-1 == dir_err)
    {
        std::cout << "barbican: Error removing file " << filename << std::endl;
        exit(1);
    }

    return 0;
}

extern "C" size_t fs_save_ocall(int64_t fd, const char *name, int64_t length)
{
    std::string file_path(name);

    std::map<std::string, std::string>::iterator iter_o = g_config_fs_outputs.find(file_path);
    std::map<std::string, strpair_t>::iterator iter_s = g_config_fs_state.find(file_path);
    if (iter_o == g_config_fs_outputs.end() && iter_s == g_config_fs_state.end()) { return -1; }

    std::string file_backup_path = (iter_o != g_config_fs_outputs.end()) ? iter_o->second : (iter_s->second).second;
    file_path = STORAGE_FS_ROOT + file_path;
    //file_backup_path = STORAGE_FS_ROOT + file_backup_path;

    std::cout << "barbican: saving " << file_path << " to " << file_backup_path << std::endl;
    std::cout << "barbican: creating " << file_backup_path << std::endl;
    std::string command; command = "mkdir -p " + file_backup_path;
    std::cout << "barbican: invoking " << command << std::endl;
    int dir_err = system(command.c_str());
    if (-1 == dir_err) {
        std::cout << "Error creating directory " << file_backup_path << std::endl; exit(1);
    }
    command = "rm -rf " + file_backup_path + "/*";
    std::cout << "barbican: invoking " << command << std::endl;
    dir_err = system(command.c_str());
    if (-1 == dir_err) {
        std::cout << "Error removing contents of directory " << file_backup_path << std::endl; exit(1);
    }

    command = "cp " + file_path + "/* " + file_backup_path + "/";
    std::cout << "barbican: invoking " << command << std::endl;
    dir_err = system(command.c_str());
    if (-1 == dir_err)
    {
        std::cout << "barbican: Error copying files from " << file_path 
            << " to " << file_backup_path << std::endl;
        exit(1);
    }

    std::string metadata_file_path = file_backup_path + "/metadata";
    std::ofstream fout;
    fout.open(metadata_file_path.c_str(), std::ios::binary | std::ios::out);
    fout.write((char *) &length, (std::streamsize) sizeof(length));
    std::cout << "barbican: Wrote " << std::to_string(sizeof(length)) << 
        " bytes to " << metadata_file_path << std::endl;
    fout.close();

    return 0;
}

extern "C" size_t fs_load_ocall(int64_t fd, const char *name, int64_t *length)
{
    std::string file_path(name);

    std::map<std::string, std::string>::iterator iter_i = g_config_fs_inputs.find(file_path);
    std::map<std::string, strpair_t>::iterator iter_s = g_config_fs_state.find(file_path);
    if (iter_i == g_config_fs_inputs.end() && iter_s == g_config_fs_state.end()) { return -1; }

    std::string file_backup_path = (iter_i != g_config_fs_inputs.end()) ? iter_i->second : (iter_s->second).first;

    file_path = STORAGE_FS_ROOT + file_path;
    //file_backup_path = STORAGE_FS_ROOT + file_backup_path;

    std::cout << "barbican: loading " << file_path << " from " << file_backup_path << std::endl;

    std::string command = "mkdir -p " + file_path;
    std::cout << "barbican: invoking " << command << std::endl;
    int dir_err = system(command.c_str());
    if (-1 == dir_err)
    {
        std::cout << "barbican: Error creating directory " << file_path << std::endl;
        exit(1);
    }
    command = "rm -rf " + file_path + "/*";
    std::cout << "barbican: invoking " << command << std::endl;
    dir_err = system(command.c_str());
    if (-1 == dir_err) {
        std::cout << "Error removing contents of directory " << file_path << std::endl; exit(1);
    }

    command = "cp " + file_backup_path + "/* " + file_path + "/";
    std::cout << "barbican: invoking " << command << std::endl;
    dir_err = system(command.c_str());
    if (-1 == dir_err)
    {
        std::cout << "barbican: Error copying files from " << 
            file_backup_path << " to " << file_path << std::endl;
        exit(1);
    }

    std::string metadata_file_path = file_backup_path + "/metadata";
    std::ifstream fin;
    fin.open(metadata_file_path, std::ios::binary | std::ios::in);
    fin.read((char *) length, (std::streamsize) sizeof(int64_t));
    std::cout << "barbican: Read " << std::to_string(sizeof(int64_t)) << 
        " bytes from " << metadata_file_path << std::endl;
    fin.close();

    assert(g_file_paths.find(fd) == g_file_paths.end()); //fd shouldn't already exist
    g_file_paths.insert(std::pair<int64_t, std::string>(fd, file_path));

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
    command = command + "rm -rf " + STORAGE_KVS_ROOT + "*";
    std::cout << "invoking " << command << std::endl;
    int dir_err = system(command.c_str());
    if (-1 == dir_err)
    {
        std::cout << "Error removing contents of directory " << STORAGE_KVS_ROOT << std::endl;
        exit(1);
    }

    command = "";
    command = command + "mkdir -p " + STORAGE_KVS_ROOT;
    std::cout << "invoking " << command << std::endl;
    dir_err = system(command.c_str());
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

    bool success = g_db_context->backend_db_create(fd, db_path.c_str());
    if (success) {
        std::cout << "barbican: created db " << fd << " at " << db_path << std::endl;
    }

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

    std::map<std::string, std::string>::iterator iter_o = g_config_kvs_outputs.find(db_path);
    std::map<std::string, strpair_t>::iterator iter_s = g_config_kvs_state.find(db_path);
    if (iter_o == g_config_kvs_outputs.end() && iter_s == g_config_kvs_state.end()) { return -1; }

    std::string db_backup_path = (iter_o != g_config_kvs_outputs.end()) ? iter_o->second : (iter_s->second).second;
    std::cout << "barbican: saving " << db_path << " to " << db_backup_path << std::endl;

    //db_backup_path = STORAGE_KVS_ROOT + db_backup_path;

    std::cout << "barbican: creating " << db_backup_path << std::endl;
    std::string command; command = "mkdir -p " + db_backup_path;
    std::cout << "barbican: invoking " << command << std::endl;
    int dir_err = system(command.c_str());
    if (-1 == dir_err) {
        std::cout << "Error creating directory " << db_backup_path << std::endl; 
        exit(1);
    }
    command = "rm -rf " + db_backup_path + "/*";
    std::cout << "barbican: invoking " << command << std::endl;
    dir_err = system(command.c_str());
    if (-1 == dir_err) {
        std::cout << "Error removing contents of directory " << db_backup_path << std::endl; exit(1);
    }

    bool success = g_db_context->backend_db_save(fd, db_backup_path.c_str());
    if (success) {
        std::cout << "barbican: saved db " << fd << " at " << db_backup_path << std::endl;
    }

    return success ? 0 : -1;
}

extern "C" size_t kvs_load_ocall(int64_t fd, const char *name)
{
    std::string db_path(name);

    std::map<std::string, std::string>::iterator iter_i = g_config_kvs_inputs.find(db_path);
    std::map<std::string, strpair_t>::iterator iter_s = g_config_kvs_state.find(db_path);
    if (iter_i == g_config_kvs_inputs.end() && iter_s == g_config_kvs_state.end()) { return -1; }

    std::string db_backup_path = (iter_i != g_config_kvs_inputs.end()) ? iter_i->second : (iter_s->second).first;
    std::cout << "barbican: loading " << db_path << " from " << db_backup_path << std::endl;

    db_path = STORAGE_KVS_ROOT + db_path;
    //db_backup_path = STORAGE_KVS_ROOT + db_backup_path;

    std::string command = "mkdir -p " + db_path;
    std::cout << "barbican: invoking " << command << std::endl;
    int dir_err = system(command.c_str());
    if (-1 == dir_err)
    {
        std::cout << "barbican: Error creating directory " << db_path << std::endl;
        exit(1);
    }
    command = "rm -rf " + db_path + "/*";
    std::cout << "barbican: invoking " << command << std::endl;
    dir_err = system(command.c_str());
    if (-1 == dir_err) {
        std::cout << "Error removing contents of directory " << db_path << std::endl; 
        exit(1);
    }

    bool success = g_db_context->backend_db_load(fd, db_path.c_str(), db_backup_path.c_str());
    return success ? 0 : -1;
}

extern "C" size_t kvs_set_ocall(int64_t fd, void *k, size_t k_len, void *buf, size_t buf_len)
{
    bool success = g_db_context->backend_db_put(fd, (uint8_t *) k, k_len, (uint8_t *) buf, buf_len);
    if (success) {
        std::cout << "barbican: wrote " << buf_len << " bytes to db " << fd << std::endl;
    }

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

uint64_t get_time(struct timeval start, struct timeval stop) {
    return (stop.tv_sec - start.tv_sec) * 1000000 + (stop.tv_usec - start.tv_usec);
}

extern "C" size_t ledger_post_ocall(const void *buf, size_t len) {
    if(client == NULL) {
        std::cout << "Ledger Client is not initialized" << std::endl;
        return  -1;
    }
//    LedgerClient *client = new LedgerClient(grpc::CreateChannel(
//            LEDGER_URL, grpc::InsecureChannelCredentials()));
    LedgerEntry ledgerEntry;
    ledgerEntry.ParseFromArray(buf, len);
    std::cout << "Creating Ledger Entry...." << std::endl;
    struct timeval start, stop;
    gettimeofday(&start, NULL);
    LedgerEntryResponse entryResponse = client->entry(ledgerEntry);
    gettimeofday(&stop, NULL);
    std::cout << "Time(micro-sec) to create ledger entry:" << get_time(start, stop) << std::endl;
    std::cout << "Done creating Ledger Entry...." << std::endl;
    delete client;
    if(entryResponse.message().compare("Failure") == 0) {
        return -1;
    }


    return  0;
}

extern "C" size_t ledger_get_policy_ocall(uint64_t policyId, void **untrusted_buf, size_t *untrusted_buf_len)
{
    if(client == NULL) {
        std::cout << "Ledger Client is not initialized" << std::endl;
        return  -1;
    }
//    LedgerClient *client = new LedgerClient(grpc::CreateChannel(
//            LEDGER_URL, grpc::InsecureChannelCredentials()));

    LedgerQueryRequest request;
    request.set_entryid(policyId);
    request.set_type(LedgerEntry_EntryType::LedgerEntry_EntryType_CREATE);
    std::cout << "Querying Ledger for Policy...." << std::endl;
    struct timeval start, stop;
    gettimeofday(&start, NULL);
    LedgerQueryResponse response = client->query(request);
    gettimeofday(&stop, NULL);
    std::cout << "Time(micro-sec) to get policy:" << get_time(start, stop) << std::endl;
    std::cout << "Done Querying Ledger...." << std::endl;
    delete client;
    if(response.entries_size() > 0) {
        LedgerEntry entry;
        for(int i = 0; i < response.entries_size(); i++) {
            entry = response.entries(i);
            if(entry.type() == LedgerEntry_EntryType_CREATE) {
                break;
            }
        }
        *untrusted_buf_len = entry.ByteSizeLong();
        *untrusted_buf = malloc(*untrusted_buf_len);
        assert(*untrusted_buf != NULL);
        entry.SerializeToArray(*untrusted_buf, *untrusted_buf_len);
        return 0;
    }
    return  -1;

}



extern "C" size_t ledger_get_compute_record_ocall(uint64_t policyId, void **untrusted_buf, size_t *untrusted_buf_len)
{
    if(client == NULL) {
        std::cout << "Ledger Client is not initialized" << std::endl;
        return  -1;
    }
//    LedgerClient *client = new LedgerClient(grpc::CreateChannel(
//            LEDGER_URL, grpc::InsecureChannelCredentials()));

    LedgerQueryRequest request;
    request.set_entryid(policyId);
    request.set_type(LedgerEntry_EntryType::LedgerEntry_EntryType_RECORD);
    std::cout << "Querying Ledger for Compute Record...." << std::endl;
    struct timeval start, stop;
    gettimeofday(&start, NULL);
    LedgerQueryResponse response = client->query(request);
    gettimeofday(&stop, NULL);
    std::cout << "Time(micro-sec) to get compute record:" << get_time(start, stop)  << std::endl;
    std::cout << "Done Querying Ledger...." << std::endl;
    int totalEntrys = response.entries_size();
    delete client;
    if( totalEntrys > 0) {
        const LedgerEntry entry = response.entries(totalEntrys-1);
        *untrusted_buf_len = entry.ByteSizeLong();
        *untrusted_buf = malloc(*untrusted_buf_len);
        assert(*untrusted_buf != NULL);
        entry.SerializeToArray(*untrusted_buf, *untrusted_buf_len);
        return 0;
    }
    return  -1;

}

extern "C" size_t ledger_get_content_ocall(uint64_t height, void **untrusted_buf, size_t *untrusted_buf_len)
{
    return  -1;
}

extern "C" size_t ledger_get_current_counter_ocall(uint64_t *height)
{
    if(client == NULL) {
        std::cout << "Ledger Client is not initialized" << std::endl;
        return  -1;
    }

//    LedgerClient *client = new LedgerClient(grpc::CreateChannel(
//            LEDGER_URL, grpc::InsecureChannelCredentials()));

    BlockchainInfoRequest blockchainInfoRequest;
    blockchainInfoRequest.set_chaincode(CHAINCODE_NAME);
    struct timeval start, stop;
    gettimeofday(&start, NULL);
    BlockchainInfoResponse resp = client->info(blockchainInfoRequest);
    gettimeofday(&stop, NULL);
    std::cout << "Time(micro-sec) to get ledger height:" << get_time(start, stop) << std::endl;

    *height = resp.height();
    delete client;

    return 0;
}

void register_fs_state(const std::string &name, 
    const std::string &backup_path_prev,
    const std::string &backup_path_next)
{
    g_config_fs_state.insert(std::pair<std::string, strpair_t>(name, 
        strpair_t(backup_path_prev, backup_path_next)));
    std::cout << "barbican: Noting that state file " << name <<
         " has prev at " << backup_path_prev << 
         " and next at " << backup_path_next << std::endl;
}

void register_fs_input(const std::string &name, const std::string &backup_path)
{
    g_config_fs_inputs.insert(std::pair<std::string, std::string>(name, backup_path));
    std::cout << "barbican: Noting that input file " << name <<
         " is backed up at " << backup_path << std::endl;
}

void register_fs_output(const std::string &name, const std::string &backup_path)
{
    g_config_fs_outputs.insert(std::pair<std::string, std::string>(name, backup_path));
    std::cout << "barbican: Noting that output file " << name <<
         " is backed up at " << backup_path << std::endl;
}

void register_kvs_state(const std::string &name, 
    const std::string &backup_path_prev,
    const std::string &backup_path_next)
{
    g_config_kvs_state.insert(std::pair<std::string, strpair_t>(name, 
        strpair_t(backup_path_prev, backup_path_next)));
    std::cout << "barbican: Noting that state db " << name <<
         " has prev at " << backup_path_prev << 
         " and next at " << backup_path_next << std::endl;
}

void register_kvs_input(const std::string &name, const std::string &backup_path)
{
    g_config_kvs_inputs.insert(std::pair<std::string, std::string>(name, backup_path));
    std::cout << "barbican: Noting that input db " << name <<
         " is backed up at " << backup_path << std::endl;
}

void register_kvs_output(const std::string &name, const std::string &backup_path)
{
    g_config_kvs_outputs.insert(std::pair<std::string, std::string>(name, backup_path));
    std::cout << "barbican: Noting that output db " << name <<
         " is backed up at " << backup_path << std::endl;
}

void register_scc_actor(const std::string &name, const std::string &ip_addr, bool role_is_server)
{
    g_config_scc_actors.insert(std::pair<std::string, std::string>(name, ip_addr));
    g_config_scc_roles.insert(std::pair<std::string, bool>(name, role_is_server));
    std::cout << "barbican: Noting that remote actor " << name << " can be reached at " << ip_addr << 
        ", we will act as " << (role_is_server ? "server" : "client") << std::endl;
}

void init_barbican(const std::string &json_file, const std::string &scratch_space_root)
{
    GOOGLE_PROTOBUF_VERIFY_VERSION;

    std::ifstream f(json_file);
    std::string json_str((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

    g_scratch_space_root = scratch_space_root;

    try {
        json j = json::parse(json_str);

        json ledger = j["ledger"];
        g_config_ledger = ledger.get<std::string>();

        json state = j["kvs_state"];
        std::cout << "barbican: Reading state config for key-value stores ..." << std::endl;
        for (json::iterator it = state.begin(); it != state.end(); ++it) {
            json prev = it.value()["prev"];
            json next = it.value()["next"];
            register_kvs_state(it.key(), prev.get<std::string>(), next.get<std::string>());
        }

        json inputs = j["kvs_inputs"];
        std::cout << "barbican: Reading input config for key-value stores ..." << std::endl;
        for (json::iterator it = inputs.begin(); it != inputs.end(); ++it) {
            register_kvs_input(it.key(), it.value().get<std::string>());
        }

        json outputs = j["kvs_outputs"];
        std::cout << "barbican: Reading output config for key-value stores ..." << std::endl;
        for (json::iterator it = outputs.begin(); it != outputs.end(); ++it) {
            register_kvs_output(it.key(), it.value().get<std::string>());
        }

        state = j["fs_state"];
        std::cout << "barbican: Reading state config for files ..." << std::endl;
        for (json::iterator it = state.begin(); it != state.end(); ++it) {
            json prev = it.value()["prev"];
            json next = it.value()["next"];
            register_fs_state(it.key(), prev.get<std::string>(), next.get<std::string>());
        }

        inputs = j["fs_inputs"];
        std::cout << "barbican: Reading input config for files ..." << std::endl;
        for (json::iterator it = inputs.begin(); it != inputs.end(); ++it) {
            register_fs_input(it.key(), it.value().get<std::string>());
        }

        outputs = j["fs_outputs"];
        std::cout << "barbican: Reading output config for files ..." << std::endl;
        for (json::iterator it = outputs.begin(); it != outputs.end(); ++it) {
            register_fs_output(it.key(), it.value().get<std::string>());
        }

        json self_addr = j["scc_self"];
        g_config_scc_self = self_addr.get<std::string>();

        json actors = j["scc_actors"];
        std::cout << "barbican: Reading network config ..." << std::endl;
        for (json::iterator it = actors.begin(); it != actors.end(); ++it) {
            json actor_info = actors[it.key()];
            json ip_addr = actor_info["url"];
            json role = actor_info["role_server"];
            register_scc_actor(it.key(), ip_addr.get<std::string>(), role.get<bool>());
        }

        client = new LedgerClient(grpc::CreateChannel(
                LEDGER_URL, grpc::InsecureChannelCredentials()));

        std::cout << "Created new client:" << client <<std::endl;

    } catch (const std::exception& ex) {
        std::cout << "barbican: Error parsing json config: " << ex.what() << std::endl;
        exit(1);
    }
}
