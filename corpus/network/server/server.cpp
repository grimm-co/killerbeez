// linux: compile with gcc -o server-linux server.cpp
// windows: compile w/ visual studio
#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <Winsock2.h>
#include <Windows.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#endif

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

#ifdef _WIN32
int tcp_listen(SOCKET * sock)
#else
int tcp_listen(int * sock)
#endif
{
	struct sockaddr_in addr;

	*sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (*sock == INVALID_SOCKET)
		return -1;
#ifndef _WIN32 // linux-only
	// https://stackoverflow.com/a/24194999
	int enable = 1;
	if (setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
	{
		printf("setsockopt failed.\n");
		return -1;
	}
#endif

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(PORT);
	if (bind(*sock, (const sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
#ifdef _WIN32
		printf("bind failed with error: %d\n", WSAGetLastError());
		closesocket(*sock);
#else
		printf("bind failed with error: %d\n", errno);
		close(*sock);
#endif
		return 1;
	}

	if (listen(*sock, SOMAXCONN) == SOCKET_ERROR) {
#ifdef _WIN32
		printf("listen failed with error: %d\n", WSAGetLastError());
		closesocket(*sock);
#else
		printf("listen failed with error: %d\n", errno);
		close(*sock);
#endif
		return 1;
	}

	return 0;
}

#ifdef _WIN32
int udp_listen(SOCKET * sock)
#else
int udp_listen(int * sock)
#endif
{
	struct sockaddr_in addr;

	*sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (*sock == INVALID_SOCKET)
		return -1;

#ifndef _WIN32 // linux-only
	// https://stackoverflow.com/a/24194999
	int enable = 1;
	if (setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
	{
		printf("setsockopt failed.\n");
		return -1;
	}
#endif

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(PORT);
	if (bind(*sock, (const sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
#ifdef _WIN32
		printf("bind failed with error: %d\n", WSAGetLastError());
		closesocket(*sock);
#else
		printf("bind failed with error: %d\n", errno);
		close(*sock);
#endif
		return 1;
	}

	return 0;
}

int main(int argc, char ** argv)
{
#ifdef _WIN32
	WSADATA wsaData;
#endif
	int i, done, forever = 0, udp = 0, num_skipped_inputs = 0;
#ifdef _WIN32
	SOCKET server = INVALID_SOCKET, client = INVALID_SOCKET;
#else
	int server = INVALID_SOCKET, client = INVALID_SOCKET;
#endif
	char buffer[4096];
	struct sockaddr_in addr;
	int addrlen = sizeof(addr);
	
	if (argc > 1 && !strcmp("-loop", argv[1]))
		forever = 1;
	if (argc > 2)
		num_skipped_inputs = atoi(argv[2]);
	if (argc > 2)
		udp = strcmp("-udp", argv[3]) == 0;

#ifdef _WIN32
	if (WSAStartup(MAKEWORD(2, 2), &wsaData))
	{
		printf("WSAStartup Failed\n");
		return 1;
	}
#endif

	if ((!udp && tcp_listen(&server)) || (udp && udp_listen(&server)))
		return 1;

	done = 0;
	while (!done || forever) {
		done = 1;

		if (udp) {
			for (i = 0; i < num_skipped_inputs; i++)
#ifdef _WIN32
				recvfrom(server, buffer, sizeof(buffer), 0, (sockaddr *)&addr, &addrlen);
#else
				recvfrom(server, buffer, sizeof(buffer), 0, (sockaddr *)&addr, (socklen_t *)&addrlen);
#endif

#ifdef _WIN32
			if (recvfrom(server, buffer, sizeof(buffer), 0, (sockaddr *)&addr, &addrlen) != SOCKET_ERROR)
#else
			if (recvfrom(server, buffer, sizeof(buffer), 0, (sockaddr *)&addr, (socklen_t *)&addrlen) != SOCKET_ERROR)
#endif
				process_data(buffer);

		} else {
			client = accept(server, NULL, NULL);
			if (client == INVALID_SOCKET) {
#ifdef _WIN32
				printf("accept failed with error: %d\n", WSAGetLastError());
				closesocket(server);
#else
				printf("accept failed with error: %d\n", errno);
				close(server);
#endif
				return 1;
			}

			for (i = 0; i < num_skipped_inputs; i++)
				recv(client, buffer, sizeof(buffer), 0);

			if (recv(client, buffer, sizeof(buffer), 0) > 0)
				process_data(buffer);
#ifdef _WIN32
			shutdown(client, SD_BOTH);
			closesocket(client);
#else
			shutdown(client, SHUT_RDWR);
			close(client);
#endif
		}
	}

#ifdef _WIN32
			closesocket(server);
#else
			close(server);
#endif
    return 0;
}

