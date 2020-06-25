#pragma once

struct pmanager;

extern bool pmanager_new(const char* name, const char* password);
extern bool pmanager_list(const char* password);
extern bool pmanager_delete(const char* name);
extern bool pmanager_delete_all();
