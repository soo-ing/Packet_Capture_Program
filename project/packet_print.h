#pragma once
#ifndef PRINT_H
#define PRINT_H
#include "set_packet.h"
#include <WinSock2.h>

class Print {
private:
	FILE *logFile;
public:
	Print(FILE *log);
	void fPrintIp(IPHeader *ip);
	void fPrintTcp(IPHeader *ip, TCPHeader *tcp);
	void fPrintUdp(IPHeader *ip, UDPHeader *udp);
	void fPrintDns(DNSHeader *dns);
	void fPrintPayload(char *app);
	void fPrintDump(char *app, int size);
	void close();
	static void printMain();
	static void printTcp(IPHeader *ip, TCPHeader *tcp);
	static void printUdp(IPHeader *ip, UDPHeader *udp);
	static void printIcmp(IPHeader *ip, ICMPHeader *icmp);
	static void printTcpApp(IPHeader *ip, TCPHeader *tcp, const char *appHeader);
	static void printUdpApp(IPHeader *ip, UDPHeader *udp, const char *appHeader);
};
#endif 