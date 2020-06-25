# pmanager
A toy but secure password manager created using C99, SQLite3 and libtomcrypt

### Usage
----------
```
pmanager list -password "pass123" - lists all passwords.
pmanager new -password "pass123" -name "example" - creates new password entry.
pmanager delete -name "example" - deletes password entry.
pmanager deleteall - deletes all password entries.
```

### How it works
----------
The user only needs to remember one main password. When creating new entries / listing all passwords, the main password is hashed using sha256 and hashed result is used as a key to encrypt/decrypt the passowrds. For encryption, pmanager uses AES/Rijndael. All passwords are saved within a local SQLite3 database file.
