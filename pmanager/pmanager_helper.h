#pragma once

extern void pmanager_usage();
extern bool pmanager_get_flag(const int argc, const char** argv, const char* flag, const char** out);

extern void pmanager_generate_password(char* out, const size_t len);

extern bool pmanager_hash(const unsigned char* in, const size_t len, unsigned char* out);

extern bool pmanager_rijndael_setup(symmetric_key* skey, const unsigned char* key, const size_t key_len);
extern bool pmanager_encrypt(symmetric_key* skey, const unsigned char* in, unsigned char* out);
extern bool pmanager_decrypt(symmetric_key* skey, const unsigned char* in, unsigned char* out);
extern void pmanager_rijndael_done(symmetric_key* skey);

extern bool pmanager_connect_db(sqlite3** db);
extern bool pmanager_setup_db(sqlite3* db);
extern void pmanager_close_db(sqlite3* db);
