#include <iostream>
#include <ws2tcpip.h>
#include <process.h>
#include <atomic>
#include "header.h"
#include "set_packet.h"
#include "packet_print.h"
#pragma comment(lib, "ws2_32.lib")
#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)

std::atomic<bool> wait(false);
unsigned int WINAPI input(void *arg) {
	char option;
	while (true) {
		option = getc(stdin);
		switch (option)
		{
		case 'q':
			wait = true;
			return 0;
			break;
		}
	}
	return 0;
}

unsigned int WINAPI sniff(void *param) {
	SOCKET s = (SOCKET)param;
	char *Buffer = new char[65536];
	int pkSize;
	Packets list = Packets();
	printf("\n * 패킷 캡쳐중 * \n");
	memset(Buffer, 0, 65536);
	Print::printMain();

	Print *print = new Print(fopen("log.txt", "w"));
	while (!wait.load())
	{
		pkSize = recvfrom(s, Buffer, 65536, 0, 0, 0);
		if (pkSize > 0)
		{
			Packet *packet = new Packet(Buffer, print, pkSize);
			list.add(packet);
		}
		else
			return 1;
	}
	print->close();
	delete print;
	delete[] Buffer;
	return 0;
}
int main() {
	WSADATA wsock;
	SOCKET s;
	struct in_addr addr;
	SOCKADDR_IN dest;
	char host[100], source_ip[20];
	char *Buffer = new char[65536];
	hostent *server;
	int optval, pkSize, i, in;
	char option;
	HANDLE hSockThread = NULL;
	DWORD dwSockThreadID = NULL;
	HANDLE hKeyThread = NULL;
	DWORD dwKeyThreadID = NULL;
	_SMALL_RECT Rect;


	Rect.Top = 0;
	Rect.Left = 0;
	Rect.Bottom = 40 - 1;
	Rect.Right = 160 - 1;
	COORD newSize = { 160,9999 };
	SetConsoleScreenBufferSize(GetStdHandle(STD_OUTPUT_HANDLE), newSize);
	SetConsoleWindowInfo(GetStdHandle(STD_OUTPUT_HANDLE), TRUE, &Rect);
	system("cls");

	if (WSAStartup(MAKEWORD(2, 2), &wsock) != 0)
	{
		fprintf(stderr, "WSAStartup() failed");
		exit(EXIT_FAILURE);
	}
	s = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (s == SOCKET_ERROR)
	{
		printf("Creation of raw socket failed.");
		return 0;
	}
	
	printf(" ---------------------------------\n");
	printf("|\t컴퓨터 네트워크           |\n");
	printf("|\t                          |\n");
	printf("|\t패킷 캡쳐 프로그램        |\n");
	printf("|\t                          |\n");
	printf("|\t2016150022 안장호         |\n");
	printf("|\t2016154033 차수빈         |\n");
	printf("|\t2016154034 천세빈         |\n");
	printf("|\t2017154044 김동윤         |\n");
	printf("|\t                          |\n");
	printf(" ---------------------------------\n");

	if (gethostname(host, sizeof(host)) == SOCKET_ERROR)
	{
		printf("Error : %d", WSAGetLastError());
		return 1;
	}
	if ((server = gethostbyname(host)) == 0)
	{
		printf("Unable to resolve.");
		return 0;
	}

	for (int i = 0; server->h_addr_list[i] != 0; ++i)
	{
		memcpy(&addr, server->h_addr_list[i], sizeof(struct in_addr));
		printf("\n사용가능한 IP 주소 : %d번째 주소 : %s\n", i, inet_ntoa(addr));
	}
	printf("\n");
	printf("「가상머신이 없다면 0번 / 가상머신이 있다면 2번을 눌러주세요」 \n");
	printf("\n");
	printf("사용할 IP 주소를 입력해주세요 : ");
	scanf("%d", &in);

	memset(&dest, 0, sizeof(dest));
	memcpy(&dest.sin_addr.s_addr, server->h_addr_list[in], sizeof(dest.sin_addr.s_addr));
	dest.sin_family = AF_INET;
	dest.sin_port = 0;

	if (bind(s, (SOCKADDR*)&dest, sizeof(dest)) == SOCKET_ERROR)
		printf(" 연결 실패 ");

	printf("\n연결 성공\n");
	i = 1;
	if (WSAIoctl(s, SIO_RCVALL, &i, sizeof(i), 0, 0, (LPDWORD)&in, 0, 0) == SOCKET_ERROR) {
		printf("WSAIoctl() failed.\n");
		perror("Error:");
		return 1;
	}
	hSockThread = (HANDLE)_beginthreadex(NULL, 0, sniff, (void*)s, 0, (unsigned*)&dwSockThreadID);
	hKeyThread = (HANDLE)_beginthreadex(NULL, 0, input, NULL, 0, (unsigned*)&dwKeyThreadID);

	WaitForSingleObject(hSockThread, INFINITE);

	closesocket(s);
	WSACleanup();

	return 0;
}