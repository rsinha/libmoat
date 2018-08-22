#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <map>

#include "rocksdb/c.h"

#include "RocksDBInterface.hpp"


RocksDBInterface::~RocksDBInterface()
{
    backend_db_disconnect_server();
}

bool RocksDBInterface::backend_db_connect_server()
{
    this->options = rocksdb_options_create();
    long cpus = sysconf(_SC_NPROCESSORS_ONLN); //# of online cores
    rocksdb_options_increase_parallelism(this->options, (int)(cpus));
    //rocksdb_options_increase_parallelism(this->options, 4);
    //rocksdb_options_optimize_level_style_compaction(this->options, 0);
    rocksdb_options_set_create_if_missing(this->options, 1);
    this->writeoptions = rocksdb_writeoptions_create();
    this->readoptions = rocksdb_readoptions_create();

    this->db_instances = new std::map<int64_t, rocksdb_t *>();

    return true;
}

bool RocksDBInterface::backend_db_disconnect_server()
{
    if (this->db_instances != NULL)
    {
        rocksdb_writeoptions_destroy(this->writeoptions);
        rocksdb_readoptions_destroy(this->readoptions);
        rocksdb_options_destroy(this->options);

        for (std::map<int64_t, rocksdb_t*>::iterator it = this->db_instances->begin(); 
            it != this->db_instances->end();
            ++it) 
        {
            rocksdb_close(it->second);
        }        
        delete this->db_instances;
        this->db_instances = NULL;
        return true;
    }
    else
    {
        return false;
    }
}

bool RocksDBInterface::backend_db_create(int64_t fd, const char *name)
{
    std::string db_path(name);
    db_path = "/tmp/barbican/" + db_path;
    char *err = NULL;
    rocksdb_t *db = rocksdb_open(this->options, db_path.c_str(), &err);
    if (err)
    {
        printf("Connection error\n");
        return false;
    }

    this->db_instances->insert(std::pair<int64_t, rocksdb_t *>(fd, db));
    return true;
}

bool RocksDBInterface::backend_db_put(int64_t fd, uint8_t *k, size_t k_len, uint8_t *v, size_t v_len)
{
    std::map<int64_t, rocksdb_t *>::iterator iter = this->db_instances->find(fd);
    if (iter == this->db_instances->end()) { return false; }

    rocksdb_t *db = iter->second;
    char *err = NULL;
    rocksdb_put(db, this->writeoptions, (const char *) k, k_len, (const char *) v, v_len, &err);
    return (!err) ? true : false;
}

bool RocksDBInterface::backend_db_get(int64_t fd, uint8_t *k, size_t k_len, uint8_t **v, size_t *v_len)
{
    std::map<int64_t, rocksdb_t *>::iterator iter = this->db_instances->find(fd);
    if (iter == this->db_instances->end()) { return false; }

    rocksdb_t *db = iter->second;
    char *err = NULL;
    *v = (uint8_t *) rocksdb_get(db, this->readoptions, (const char *) k, k_len, v_len, &err);

    return (!err && (*v != NULL));
}

bool RocksDBInterface::backend_db_free(void *obj)
{
    free(obj);
    return true;
}

bool RocksDBInterface::backend_db_insert(int64_t fd, uint8_t *k, size_t k_len, uint8_t *v, size_t v_len)
{
    return backend_db_put(fd, k, k_len, v, v_len);
}

bool RocksDBInterface::backend_db_delete(int64_t fd, uint8_t *k, size_t k_len)
{
    std::map<int64_t, rocksdb_t *>::iterator iter = this->db_instances->find(fd);
    if (iter == this->db_instances->end()) { return false; }

    rocksdb_t *db = iter->second;
    char *err = NULL;
    rocksdb_delete(db, this->writeoptions, (const char *) k, k_len, &err);

    return (!err) ? true : false;
}

/*
bool RocksDBInterface::backend_db_delete_all()
{
    char *err = NULL;
    const char DBPath[] = "/tmp/rocksdb.dmp";
    rocksdb_close(this->rocksdb);
    rocksdb_destroy_db(this->options, DBPath, &err); 
    rocksdb_writeoptions_destroy(this->writeoptions);
    rocksdb_readoptions_destroy(this->readoptions);
    rocksdb_options_destroy(this->options);
    if (err) { return false; }
    return backend_db_connect_db_server();
}
*/
