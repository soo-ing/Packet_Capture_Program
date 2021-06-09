#pragma once
#ifndef PACKET_H
#define PACKET_H
#include "header.h"
class Print;
class Packet {
private:
	IPHeader *ip;
	UDPHeader *udp = NULL;
	TCPHeader *tcp = NULL;
	ICMPHeader *icmp = NULL;
	DNSHeader *dns;
	char *app;
	bool tcpCheck = false;
	bool udpCheck = false;
	bool icmpCheck = false;
public:
	Packet(char *packet, Print *print, int size);
	~Packet();
	char *getPayload();
	void setTcpPayload(char *packet, int ipLen);
	void setUdpPayload(char *packet, int ipLen);
	int getPort(int dest, int source);
};
class Packets {
private:
	std::vector<Packet*> list;
public:
	Packets() {}
	~Packets() {}
	void add(Packet *temp);

	Packet *getPacket(int index);

};
#endif