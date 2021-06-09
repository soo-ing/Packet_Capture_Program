#pragma once
#ifndef RAW_H
#define RAW_H

#include <vector>

#define HTTP 80
#define DNS 53
#define ICMP 1
#define TCP 6
#define UDP 17



typedef struct ip
{
	unsigned char ipHeaderLength : 4;
	unsigned char ipVer : 4; 
	unsigned char ipTos; 
	unsigned short ipTotalLength; 
	unsigned short ipId; 

	unsigned char ipFragOffset : 5;

	unsigned char ipMoreFragment : 1;
	unsigned char ipDontFragment : 1;
	unsigned char ipReservedZero : 1;

	unsigned char ipFragOffset1;

	unsigned char ipTTL; 
	unsigned char ipProtocol; 
	unsigned short ipChecksum; 
	unsigned int ipSrcaddr;
	unsigned int ipDestaddr; 
} IPV4H;

typedef struct tcp
{
	unsigned short sourcePort; 
	unsigned short destPort; 
	unsigned int sequence; 
	unsigned int acknowledge; 

	unsigned char ns : 1; 
	unsigned char reservedPart1 : 3;
	unsigned char dataOffset : 4; 
								  

	unsigned char fin : 1; 
	unsigned char syn : 1; 
	unsigned char rst : 1;
	unsigned char psh : 1; 
	unsigned char ack : 1; 
	unsigned char urg : 1; 

	unsigned char ecn : 1; 
	unsigned char cwr : 1; 

						  

	unsigned short window;
	unsigned short checksum; 
	unsigned short urgentPointer; 
} TCPH;

typedef struct udp
{
	unsigned short sourcePort; 
	unsigned short destPort; 
	unsigned short udpLength;
	unsigned short udpChecksum; 
} UDPH;

typedef struct icmp
{
	unsigned char icmp_type;
	unsigned char icmp_code;
	unsigned short icmp_checksum;
}ICMPH;

typedef struct dns
{
	unsigned short id;

	unsigned char rd : 1; 
	unsigned char tc : 1; 
	unsigned char aa : 1; 
	unsigned char opcode : 4; 
	unsigned char qr : 1; 

	unsigned char rcode : 4; 
	unsigned char cd : 1; 
	unsigned char ad : 1; 
	unsigned char z : 1; 
	unsigned char ra : 1; 

	unsigned short qCount; 
	unsigned short ansCount; 
	unsigned short authCount; 
	unsigned short addCount; 
} DNSH;
#endif