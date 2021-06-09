#pragma once
#ifndef HEADER_H
#define HEADER_H
#include "raw_socket.h"

class IPHeader {
private:
	IPV4H *header;
public:
	IPHeader();
	IPHeader(char *packet);
	unsigned int getDesaddr();
	unsigned int getSrcaddr();
	unsigned char getProtocol();
	unsigned short getIpLength();
	unsigned char getIpVer();
	unsigned char getIpTos();
	unsigned short getIpChecksum();
	unsigned char getIpHLen();
	unsigned short getIpId();
	unsigned char getTTL();

};

class TCPHeader {
private:
	TCPH *header;
public:
	TCPHeader(int ipSize, char *packet);
	unsigned short getDesPort();
	unsigned short getSrcPort();
	unsigned char getTcpLength();
	unsigned int getSeqNo();
	unsigned int getAckNo();
	unsigned char getUrg();
	unsigned char getAck();
	unsigned char getPush();
	unsigned char getRes();
	unsigned char getSyn();
	unsigned char getFin();
	unsigned short getWin();
	unsigned short getChecksum();
	unsigned short getUrgPointer();
};

class UDPHeader {
private:
	UDPH *header;
public:
	UDPHeader(int ipSize, char *packet);
	unsigned short getDesPort();
	unsigned short getSrcPort();
	unsigned short getUdpLength();
	unsigned short getUdpChecksum();
};

class ICMPHeader {
private:
	ICMPH *header;
public:
	ICMPHeader(int ipSize, char *packet);

	unsigned short getType();
	unsigned short getCode();
	unsigned short getChecksum();
};

class DNSHeader {
private:
	DNSH *header;
public:
	DNSHeader();
	DNSHeader(int headerSize, char *packet);
	unsigned short getQCount();
	unsigned short getAnsCount();
	unsigned short getAuthCount();
	unsigned short getAddCount();
};
#endif