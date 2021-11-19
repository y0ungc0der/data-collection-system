#include "client.h"
#include "server.h"
#include <locale.h>

int wrongArgs()
{
	printf("%s\n", "Use this format for args: --type [server/client]");
	system("pause");

	return 0;
}

int main(int argc, char *argv[])
{
	//debugging();
	//system("pause");
	//return;

	setlocale(LC_ALL, "rus");

	if (argc != 3 || strcmp(argv[1], "--type") != 0)
		return wrongArgs();

	if (strcmp(argv[2], "client") == 0)
	{
		char host[32], port_str[8];
		unsigned port;

		while (1)
		{
			printf("Enter IP: ");
			gets(host);
			printf("Enter port: ");
			port = atoi(gets(port_str));

			int c = client(host, port);
			printf("Client closed with code: %d\n", c);
			system("pause & cls");
		}
	} else if (strcmp(argv[2], "server") == 0)
	{
		char port_str[8];
		unsigned port;

		while (1)
		{
			printf("Enter port: ");
			port = atoi(gets(port_str));

			int s = io_serv(port);
			printf("Server closed with code: %d\n", s);
			system("pause & cls");
		}
	}
	else
		return wrongArgs();

	return 0;
}

char * scan_line(char *line)
{
	int ch;
	line[0] = '\0';

	for (int index = 0; ((ch = getchar()) != '\r') && (ch != '\n') && (ch != EOF); index++)
	{
		line[index] = (char)ch; // Type casting 'int' to 'char'.
		line[index + 1] = '\0'; // Inserting null character at the end.
	}

	return line;
}