#include "stdinc.h"

#include "pmanager_helper.h"
#include "pmanager.h"

struct pmanager
{
	symmetric_key skey;
	sqlite3* db;

	unsigned char password_hash[32];
};

int pmanager_list_callback(struct pmanager* pm, const int argc, const char** argv, const char** column)
{
	if (!pmanager_rijndael_setup(&pm->skey, pm->password_hash, sizeof(pm->password_hash)))
	{
		return SQLITE_ABORT;
	}

	for (int i = 0; i < argc; i++)
	{
		if (!strcmp(column[i], "name"))
		{
			printf("%s: ", argv[i]);
		}
		else
		{
			const unsigned char* encrypted_password = (const unsigned char*)argv[i];
			const unsigned char decrypted_password[32] = { 0 };

			if (!pmanager_decrypt(&pm->skey, encrypted_password, decrypted_password) || !pmanager_decrypt(&pm->skey, &encrypted_password[16], &decrypted_password[16]))
			{
				return SQLITE_ABORT;
			}

			printf("%s\n", (const char*)decrypted_password);
		}
	}

	pmanager_rijndael_done(&pm->skey);
	return SQLITE_OK;
}

bool pmanager_new(const char* name, const char* password)
{
	struct pmanager pm = { 0 };
	if (!pmanager_hash(password, strlen(password), pm.password_hash))
	{
		return false;
	}

	unsigned char generated_password[32] = { 0 };
	pmanager_generate_password((char*)generated_password, sizeof(generated_password));

	unsigned char encrypted_password[sizeof(generated_password)] = { 0 };

	if (!pmanager_rijndael_setup(&pm.skey, pm.password_hash, sizeof(pm.password_hash)))
	{
		return false;
	}
	
	if (!pmanager_encrypt(&pm.skey, generated_password, encrypted_password) || !pmanager_encrypt(&pm.skey, &generated_password[16], &encrypted_password[16]))
	{
		pmanager_rijndael_done(&pm.skey);
		return false;
	}

	pmanager_rijndael_done(&pm.skey);

	if (!pmanager_connect_db(&pm.db))
	{
		return false;
	}

	sqlite3_stmt* stmt = NULL;

	if (sqlite3_prepare_v2(pm.db, "INSERT INTO passwords (name, encrypted_password) VALUES (?, ?)", -1, &stmt, NULL) != SQLITE_OK)
	{
		printf("sqlite3_prepare_v2 failed: %s\n", sqlite3_errmsg(pm.db));
		goto db_error;
	}

	if (sqlite3_bind_text(stmt, 1, name, -1, NULL) != SQLITE_OK)
	{
		printf("sqlite3_bind_text failed: %s\n", sqlite3_errmsg(pm.db));
		goto db_error;
	}

	if (sqlite3_bind_blob(stmt, 2, encrypted_password, sizeof(encrypted_password), NULL) != SQLITE_OK)
	{
		printf("sqlite3_bind_blob failed: %s\n", sqlite3_errmsg(pm.db));
		goto db_error;
	}

	if (sqlite3_step(stmt) != SQLITE_DONE)
	{
		printf("sqlite3_step failed: %s\n", sqlite3_errmsg(pm.db));
		goto db_error;
	}

	printf("Generated passowrd for \"%s\": %s\n", name, generated_password);

	pmanager_close_db(pm.db);
	return true;

db_error:
	if (pm.db)
	{
		pmanager_close_db(pm.db);
	}

	return false;
}

bool pmanager_list(const char* password)
{
	struct pmanager pm = { 0 };
	if (!pmanager_hash(password, strlen(password), pm.password_hash))
	{
		return false;
	}

	if (!pmanager_connect_db(&pm.db))
	{
		return false;
	}

	char* err = NULL;
	sqlite3_exec(pm.db, "SELECT name, encrypted_password FROM passwords", &pmanager_list_callback, &pm, &err);

	if (err)
	{
		printf("sqlite3_exec failed: %s\n", err);
		
		sqlite3_free(err);
		pmanager_close_db(pm.db);
		return false;
	}

	pmanager_close_db(pm.db);
	return true;
}

bool pmanager_delete(const char* name)
{
	sqlite3* db = NULL;

	if (!pmanager_connect_db(&db))
	{
		return false;
	}

	sqlite3_stmt* stmt = NULL;

	if (sqlite3_prepare_v2(db, "DELETE FROM passwords WHERE name = ?", -1, &stmt, 0) != SQLITE_OK)
	{
		printf("sqlite3_prepare_v2 failed: %s\n", sqlite3_errmsg(db));
		goto db_error;
	}

	if (sqlite3_bind_text(stmt, 1, name, -1, NULL) != SQLITE_OK)
	{
		printf("sqlite3_bind_text failed: %s\n", sqlite3_errmsg(db));
		goto db_error;
	}

	if (sqlite3_step(stmt) != SQLITE_DONE)
	{
		printf("sqlite3_step failed: %s\n", sqlite3_errmsg(db));
		goto db_error;
	}

	pmanager_close_db(db);
	return true;

db_error:
	pmanager_close_db(db);
	return false;
}

bool pmanager_delete_all()
{
	sqlite3* db;

	if (!pmanager_connect_db(&db))
	{
		return false;
	}

	char* err = NULL;
	sqlite3_exec(db, "DELETE FROM passwords", NULL, NULL, &err);

	if (err)
	{
		printf("sqlite3_exec failed: %s\n", err);

		sqlite3_free(err);
		pmanager_close_db(&db);
		return false;
	}

	pmanager_close_db(db);
	return true;
}
