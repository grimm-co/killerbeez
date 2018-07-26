#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <Winsock2.h>
#include <Windows.h>

#include <stdio.h>

// This program crashes if it receives ABCD on a socket from a server.
// You can test it by doing: nc -l 4444, ./client.exe in another shell,
// and typing the input you want to send in the nc window.

// Note that VisualStudio will not overwrite the binaries already 
// included with Killerbeez. (corpus/network/{client,server}.exe)
// It will instead put newly-compiled binaries in corpus/network/x64.

void process_data(char * buffer)
{
	char * nil = NULL;
	if (buffer[0] == 'A')
	{
		if (buffer[1] == 'B')
		{
			if (buffer[2] == 'C')
			{
				if (buffer[3] == 'D')
				{
					*nil = 'E';
				}
				else
				{
					printf("Wrong 3\n");
				}
			}
			else
			{
				printf("Wrong 2\n");
			}
		}
		else
		{
			printf("Wrong 1\n");
		}
	}
	else
	{
		printf("Wrong 0\n");
	}
}


int main(int argc, char ** argv)
{
	WSADATA wsaData;
	SOCKET sock = INVALID_SOCKET;
	struct sockaddr_in addr;
	int result, port;
	char buffer[512];
	const char * ip;

	if (argc < 3) {
		printf("Using 127.0.0.1:4444\n");
		ip = "127.0.0.1";
		port = 4444;
	}
	else
	{
		ip = argv[1];
		port = atoi(argv[2]);
	}

	if (WSAStartup(MAKEWORD(2, 2), &wsaData))
	{
		printf("WSAStartup Failed\n");
		return 1;
	}

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET)
		return -1;

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(ip);
	addr.sin_port = htons(port);
	if (connect(sock, (SOCKADDR *)&addr, sizeof(addr)) == SOCKET_ERROR)
		return -1;
	printf("Connected.\n");

	result = recv(sock, buffer, sizeof(buffer) - 1, 0);
	if (result > 0)
		printf("Received: %s", buffer);

	process_data(buffer);

	shutdown(sock, SD_BOTH);
	closesocket(sock);
    return 0;
}

