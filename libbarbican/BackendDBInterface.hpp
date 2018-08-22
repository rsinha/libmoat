#ifndef VERITASDB_INCLUDE_VERITAS_UNTRUSTEDDB_H_
#define VERITASDB_INCLUDE_VERITAS_UNTRUSTEDDB_H_

#include <stdint.h>

class BackendDBInterface
{
public:
  virtual      ~BackendDBInterface() { }
  virtual bool  backend_db_connect_server() = 0;
  virtual bool  backend_db_disconnect_server() = 0;
  virtual bool  backend_db_create(int64_t fd, const char *name) = 0;
  virtual bool  backend_db_get(int64_t fd, uint8_t *k, size_t k_len, uint8_t **v, size_t *v_len) = 0;
  virtual bool  backend_db_free(void *obj) = 0;
  virtual bool  backend_db_put(int64_t fd, uint8_t *k, size_t k_len, uint8_t *v, size_t v_len) = 0;
  virtual bool  backend_db_insert(int64_t fd, uint8_t *k, size_t k_len, uint8_t *v, size_t v_len) = 0;
  virtual bool  backend_db_delete(int64_t fd, uint8_t *k, size_t k_len) = 0;
};

#endif
