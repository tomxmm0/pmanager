#include "stdinc.h"

#include "pmanager_helper.h"
#include "pmanager.h"

int main(int argc, char** argv)
{
	if (argc < 2)
	{
		pmanager_usage();
	}
	else
	{
		if (!strcmp(argv[1], "new") && argc == 6)
		{
			const char* name;
			const char* password;

			if (pmanager_get_flag(argc, argv, "name", &name) && pmanager_get_flag(argc, argv, "password", &password))
			{
				srand(time(0));

				if (!pmanager_new(name, password))
				{
					printf("Could not create new password entry.\n");
					return 1;
				}
			}
			else
			{
				pmanager_usage();
			}
		}
		else if (!strcmp(argv[1], "list") && argc == 4)
		{
			const char* password;

			if (pmanager_get_flag(argc, argv, "password", &password))
			{
				if (!pmanager_list(password))
				{
					printf("Could not list passwords.\n");
					return 1;
				}
			}
			else
			{
				pmanager_usage();
			}
		}
		else if (!strcmp(argv[1], "delete") && argc == 4)
		{
			const char* name;

			if (pmanager_get_flag(argc, argv, "name", &name))
			{
				if (!pmanager_delete(name))
				{
					printf("Could not delete password entry.\n");
					return 1;
				}
			}
			else
			{
				pmanager_usage();
			}
		}
		else if (!strcmp(argv[1], "deleteall") && argc == 2)
		{
			if (!pmanager_delete_all())
			{
				printf("Could not delete passwords.\n");
				return 1;
			}
		}
		else
		{
			pmanager_usage();
		}
	}

	return 0;
}
