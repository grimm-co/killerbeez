#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <Winsock2.h>
#include <Windows.h>

#include <stdio.h>

#define PORT 4444

// this program will listen on 127.0.0.1:4444 and crash if it receives the
// input "ABCD".

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

int tcp_listen(SOCKET * sock)
{
	struct sockaddr_in addr;

	*sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (*sock == INVALID_SOCKET)
		return -1;

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(PORT);
	if (bind(*sock, (const sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
		printf("bind failed with error: %d\n", WSAGetLastError());
		closesocket(*sock);
		return 1;
	}

	if (listen(*sock, SOMAXCONN) == SOCKET_ERROR) {
		printf("listen failed with error: %d\n", WSAGetLastError());
		closesocket(*sock);
		return 1;
	}

	return 0;
}

int udp_listen(SOCKET * sock)
{
	struct sockaddr_in addr;

	*sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (*sock == INVALID_SOCKET)
		return -1;

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(PORT);
	if (bind(*sock, (const sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
		printf("bind failed with error: %d\n", WSAGetLastError());
		closesocket(*sock);
		return 1;
	}

	return 0;
}

int main(int argc, char ** argv)
{
	WSADATA wsaData;
	int i, done, forever = 0, udp = 0, num_skipped_inputs = 0;
	SOCKET server = INVALID_SOCKET, client = INVALID_SOCKET;
	char buffer[4096];
	struct sockaddr_in addr;
	int addrlen = sizeof(addr);
	
	if (argc > 1 && !strcmp("-loop", argv[1]))
		forever = 1;
	if (argc > 2)
		num_skipped_inputs = atoi(argv[2]);
	if (argc > 2)
		udp = strcmp("-udp", argv[3]) == 0;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData))
	{
		printf("WSAStartup Failed\n");
		return 1;
	}

	if ((!udp && tcp_listen(&server)) || (udp && udp_listen(&server)))
		return 1;

	done = 0;
	while (!done || forever) {
		done = 1;

		if (udp) {
			for (i = 0; i < num_skipped_inputs; i++)
				recvfrom(server, buffer, sizeof(buffer), 0, (sockaddr *)&addr, &addrlen);

			if (recvfrom(server, buffer, sizeof(buffer), 0, (sockaddr *)&addr, &addrlen) != SOCKET_ERROR)
				process_data(buffer);

		} else {
			client = accept(server, NULL, NULL);
			if (client == INVALID_SOCKET) {
				printf("accept failed with error: %d\n", WSAGetLastError());
				closesocket(server);
				return 1;
			}

			for (i = 0; i < num_skipped_inputs; i++)
				recv(client, buffer, sizeof(buffer), 0);

			if (recv(client, buffer, sizeof(buffer), 0) > 0)
				process_data(buffer);
			shutdown(client, SD_BOTH);
			closesocket(client);
		}
	}

	closesocket(server);
    return 0;
}

