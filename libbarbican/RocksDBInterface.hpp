#ifndef ROCKSDB_INTERFACE_H_
#define ROCKSDB_INTERFACE_H_

#include "BackendDBInterface.hpp"
#include <map>
#include "rocksdb/c.h"

class RocksDBInterface : public BackendDBInterface
{
private:
  std::map<int64_t, rocksdb_t *> *db_instances;
  rocksdb_options_t *options;
  rocksdb_writeoptions_t *writeoptions;
  rocksdb_readoptions_t *readoptions;

public:
  ~RocksDBInterface();
  bool  backend_db_connect_server();
  bool  backend_db_disconnect_server();
  bool  backend_db_create(int64_t fd, const char *name);
  bool  backend_db_get(int64_t fd, uint8_t *k, size_t k_len, uint8_t **v, size_t *v_len);
  bool  backend_db_free(void *obj);
  bool  backend_db_put(int64_t fd, uint8_t *k, size_t k_len, uint8_t *v, size_t v_len);
  bool  backend_db_insert(int64_t fd, uint8_t *k, size_t k_len, uint8_t *v, size_t v_len);
  bool  backend_db_delete(int64_t fd, uint8_t *k, size_t k_len);
  bool  backend_db_save(int64_t fd, const char *name);
  bool  backend_db_reload(int64_t fd, const char *db_path, const char *db_backup_path);
};

#endif
