#include "stdinc.h"
#include "pmanager_helper.h"

void pmanager_usage()
{
	printf("\npmanager usage:\n");
	printf(
		"pmanager list -password \"pass123\" - lists all passwords.\n"
		"pmanager new -password \"pass123\" -name \"example\" - creates new password entry.\n"
		"pmanager delete -name \"example\" - deletes password entry.\n"
		"pmanager deleteall - deletes all password entries.\n\n");
}

bool pmanager_get_flag(const int argc, const char** argv, const char* flag, const char** out)
{
	for (int i = 0; i < argc; i++)
	{
		if (argv[i][0] == '-' && !strcmp(&argv[i][1], flag))
		{
			if (i + 1 == argc)
			{
				return false;
			}
			else
			{
				*out = argv[i + 1];
				return true;
			}
		}
	}

	return false;
}

void pmanager_generate_password(char* out, const size_t len)
{
	for (int i = 0; i < len - 1; i++)
	{
		out[i] = 33 + rand() % 94;
	}

	out[len - 1] = 0;
}

bool pmanager_hash(const unsigned char* in, const size_t len, unsigned char* out)
{
	hash_state hs;
	int err = CRYPT_OK;

	if ((err = sha256_init(&hs)) != CRYPT_OK)
	{
		printf("sha256_init failed: %s\n", error_to_string(err));
		return false;
	}

	if ((err = sha256_process(&hs, in, len)) != CRYPT_OK)
	{
		printf("sha256_process failed: %s\n", error_to_string(err));
		return false;
	}

	if ((err = sha256_done(&hs, out)) != CRYPT_OK)
	{
		printf("sha256_done failed: %s\n", error_to_string(err));
		return false;
	}

	return true;
}

bool pmanager_rijndael_setup(symmetric_key* skey, const unsigned char* key, const size_t key_len)
{
	int err = CRYPT_OK;

	if ((err = rijndael_setup(key, key_len, 0, skey)) != CRYPT_OK)
	{
		printf("rijndael_setup failed: %s\n", error_to_string(err));
		return false;
	}

	return true;
}

bool pmanager_encrypt(symmetric_key* skey, const unsigned char* in, unsigned char* out)
{
	int err;

	if ((err = rijndael_ecb_encrypt(in, out, skey)) != CRYPT_OK)
	{
		printf("rijndael_ecb_encrypt failed: %s\n", error_to_string(err));
		return false;
	}

	return true;
}

bool pmanager_decrypt(symmetric_key* skey, const unsigned char* in, unsigned char* out)
{
	int err;

	if ((err = rijndael_ecb_decrypt(in, out, skey)) != CRYPT_OK)
	{
		printf("rijndael_ecb_decrypt failed: %s\n", error_to_string(err));
		return false;
	}

	return true;
}

void pmanager_rijndael_done(symmetric_key* skey)
{
	rijndael_done(skey);
	skey = NULL;
}

bool pmanager_connect_db(sqlite3** db)
{
	if (sqlite3_open("passwords.db", db) != SQLITE_OK)
	{
		printf("sqlite3_open failed: %s\n", sqlite3_errmsg(*db));

		pmanager_close_db(*db);
		return false;
	}

	return pmanager_setup_db(*db);
}

bool pmanager_setup_db(sqlite3* db)
{
	char* err = NULL;
	sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS passwords (name TEXT NOT NULL, encrypted_password BLOB NOT NULL)", NULL, NULL, &err);

	if (err)
	{
		printf("sqlite3_exec failed: %s\n", err);

		sqlite3_free(err);
		return false;
	}

	return true;
}

void pmanager_close_db(sqlite3* db)
{
	sqlite3_close_v2(db);
}
