#include "packet_print.h"

Print::Print(FILE *log) {
	if (log == NULL)
	{
		printf("Unable to create file.");
		exit(1);
	}
	this->logFile = log;
}

void Print::fPrintIp(IPHeader *ip) {
	SOCKADDR_IN source, dest;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ip->getSrcaddr();

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = ip->getDesaddr();
	fprintf(logFile, "======================================\n");
	fprintf(logFile, "| IP Header\t\t\t\t\t|\n");
	fprintf(logFile, "======================================\n");
	fprintf(logFile, "| Version\t| IHL\t\t\t| TOS\t\t|\n");
	fprintf(logFile, "-------------------------------------------------------------------\n");
	fprintf(logFile, "| %d\t| %d DWORDS or %d Bytes\t| %d\t\t|\n", (unsigned int)ip->getIpVer(), (unsigned int)ip->getIpHLen(),
		((unsigned int)(ip->getIpHLen()) * 4), (unsigned int)ip->getIpTos());
	fprintf(logFile, "-------------------------------------------------------------------\n");
	fprintf(logFile, "| IP Total Length\t\t\t\t\t|\n");
	fprintf(logFile, "-------------------------------------------------------------------\n");
	fprintf(logFile, "| %d Bytes(Size of Packet)\t\t\t\t|\n", ntohs(ip->getIpLength()));
	fprintf(logFile, "-------------------------------------------------------------------\n");
	fprintf(logFile, "| Identification\t\t\t\t\t|\n");
	fprintf(logFile, "-------------------------------------------------------------------\n");
	fprintf(logFile, "| %d\t\t\t\t\t\t|\n", ntohs(ip->getIpId()));
	fprintf(logFile, "-------------------------------------------------------------------\n");
	fprintf(logFile, "| TTL\t| Protocol\t\t| Checksum\t\t|\n");
	fprintf(logFile, "-------------------------------------------------------------------\n");
	fprintf(logFile, "| %d\t| %d\t\t| %d\t\t\t|\n", (unsigned int)ip->getTTL(), (unsigned int)ip->getProtocol(), ntohs(ip->getIpChecksum()));
	fprintf(logFile, "-------------------------------------------------------------------\n");
	fprintf(logFile, "| Source IP\t\t\t\t\t|\n");
	fprintf(logFile, "-------------------------------------------------------------------\n");
	fprintf(logFile, "| %s\t\t\t\t\t|\n", inet_ntoa(source.sin_addr));
	fprintf(logFile, "-------------------------------------------------------------------\n");
	fprintf(logFile, "| Destination IP\t\t\t\t\t|\n");
	fprintf(logFile, "-------------------------------------------------------------------\n");
	fprintf(logFile, "| %s\t\t\t\t\t|\n", inet_ntoa(dest.sin_addr));
	fprintf(logFile, "-------------------------------------------------------------------\n");
	fprintf(logFile, "\n");
}

void Print::close() {
	if (fclose(logFile) == -1)
	{
		printf("파일 닫기 에러");
		exit(1);
	}
}

void Print::fPrintTcp(IPHeader *ip, TCPHeader *tcp) {
	fprintf(logFile, "======================================\n");
	fprintf(logFile, "| TCP Header\t\t\t\t\t|\n");
	fprintf(logFile, "======================================\n");
	fprintf(logFile, "| Source Port\t\t| Destination Port\t\t|\n");
	fprintf(logFile, "-------------------------------------------------------------------\n");
	fprintf(logFile, "| %u\t\t\t| %u\t\t\t|\n", ntohs(tcp->getSrcPort()), ntohs(tcp->getDesPort()));
	fprintf(logFile, "-------------------------------------------------------------------\n");
	fprintf(logFile, "| Sequence Number\t\t\t\t|\n");
	fprintf(logFile, "-------------------------------------------------------------------\n");
	fprintf(logFile, "| %u\t\t\t\t\t|\n", ntohl(tcp->getSeqNo()));
	fprintf(logFile, "-------------------------------------------------------------------\n");
	fprintf(logFile, "| Acknowledge Number\t\t\t\t|\n");
	fprintf(logFile, "-------------------------------------------------------------------\n");
	fprintf(logFile, "| %u\t\t\t\t\t|\n", ntohl(tcp->getAckNo()));
	fprintf(logFile, "-------------------------------------------------------------------\n");
	fprintf(logFile, "| Header Length : %d DWORDS or %d BYTES\t\t|\n"
		, (unsigned int)tcp->getTcpLength(), (unsigned int)tcp->getTcpLength() * 4);
	fprintf(logFile, "| Urgent Flag : %d\t\t\t\t\t|\n", (unsigned int)tcp->getUrg());
	fprintf(logFile, "| Acknowledgement Flag : %d\t\t\t\t|\n", (unsigned int)tcp->getAck());
	fprintf(logFile, "| Push Flag : %d\t\t\t\t\t|\n", (unsigned int)tcp->getPush());
	fprintf(logFile, "| Reset Flag : %d\t\t\t\t\t|\n", (unsigned int)tcp->getRes());
	fprintf(logFile, "| Synchronise Flag : %d\t\t\t\t|\n", (unsigned int)tcp->getSyn());
	fprintf(logFile, "| Finish Flag : %d\t\t\t\t\t|\n", (unsigned int)tcp->getFin());
	fprintf(logFile, "| Window : %d\t\t\t\t\t|\n", ntohs(tcp->getWin()));
	fprintf(logFile, "-------------------------------------------------------------------\n");
	fprintf(logFile, "| Checksum\t\t| Urgent Pointer\t\t|\n");
	fprintf(logFile, "-------------------------------------------------------------------\n");
	fprintf(logFile, "| %u\t\t\t| %u\t\t\t|\n", ntohs(tcp->getChecksum()), tcp->getUrgPointer());
	fprintf(logFile, "-------------------------------------------------------------------\n");
	fprintf(logFile, "\n");
	fPrintIp(ip);
}

void Print::fPrintUdp(IPHeader *ip, UDPHeader *udp) {
	fprintf(logFile, "======================================\n");
	fprintf(logFile, "| UDP Header\t\t\t\t\t|\n");
	fprintf(logFile, "======================================\n");
	fprintf(logFile, "| Source Port\t\t| Destination Port\t\t|\n");
	fprintf(logFile, "-------------------------------------------------------------------\n");
	fprintf(logFile, "| %u\t\t\t| %u\t\t\t|\n", ntohs(udp->getSrcPort()), ntohs(udp->getDesPort()));
	fprintf(logFile, "-------------------------------------------------------------------\n");
	fprintf(logFile, "| Length\t\t\t| Checksum\t\t|\n");
	fprintf(logFile, "-------------------------------------------------------------------\n");
	fprintf(logFile, "| %u\t\t\t| %u\t\t\t|\n", ntohs(udp->getUdpLength()), ntohs(udp->getUdpChecksum()));
	fprintf(logFile, "-------------------------------------------------------------------\n");
	fPrintIp(ip);
}

void Print::fPrintDns(DNSHeader *dns) {
	fprintf(logFile, "\nThe response contains : ");
	fprintf(logFile, "\n %d Questions.", ntohs(dns->getQCount()));
	fprintf(logFile, "\n %d Answers.", ntohs(dns->getAnsCount()));
	fprintf(logFile, "\n %d Authoritative Servers.", ntohs(dns->getAuthCount()));
	fprintf(logFile, "\n %d Additional records.\n\n", ntohs(dns->getAddCount()));

}

void Print::fPrintPayload(char *app) {
	fprintf(logFile, "\n%s\n", app);
}

void Print::fPrintDump(char *app, int size) {


	for (int i = 0; i < size; i++)
	{
		if (i != 0 && i % 16 == 0)   
		{
			for (int j = i - 16; j < i; j++)
			{
				if (app[j] >= 32 && app[j] <= 128) {
					fprintf(logFile, "%c", (unsigned char)app[j]);
				}
				else {
					fprintf(logFile, "."); 

				}
			}
			fprintf(logFile, "\n");
		}

		if (i % 16 == 0) {
			fprintf(logFile, "	");
		}

		fprintf(logFile, " %02X", (unsigned int)app[i]);


		if (i == size - 1)  
		{
			for (int j = 0; j < 15 - i % 16; j++) {
				fprintf(logFile, "   "); 
			}

			fprintf(logFile, "         ");


			for (int j = i - i % 16; j <= i; j++)
			{
				if (app[j] >= 32 && app[j] <= 128) {
					fprintf(logFile, "%c", (unsigned char)app[j]);
				}
				else {
					fprintf(logFile, ".");

				}
			}
			fprintf(logFile, "\n");
		}
	}

}

void Print::printTcp(IPHeader *ip, TCPHeader *tcp) {
	SOCKADDR_IN source, dest;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = (unsigned int)ip->getSrcaddr();

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = (unsigned int)ip->getDesaddr();
	printf("프로토콜:TCP\n");
	printf("출발지 주소:%s\n", strdup(inet_ntoa(source.sin_addr)));
	printf("목적지 주소:%s\n", strdup(inet_ntoa(dest.sin_addr)));
	printf("출발Port/TTL:%u\n", ntohs(tcp->getSrcPort()));
	printf("목적Port:%u\n", ntohs(tcp->getDesPort()));
	printf("-------------------------------------------\n");
	printf("-------------------------------------------\n");
}

void Print::printUdp(IPHeader *ip, UDPHeader *udp) {
	SOCKADDR_IN source, dest;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ip->getSrcaddr();

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = ip->getDesaddr();
	printf("프로토콜:UDP\n");
	printf("출발지 주소:%s\n", strdup(inet_ntoa(source.sin_addr)));
	printf("목적지 주소:%s\n", strdup(inet_ntoa(dest.sin_addr)));
	printf("출발Port/TTL:%u\n", ntohs(udp->getSrcPort()));
	printf("목적Port:%u\n", ntohs(udp->getDesPort()));
	printf("-------------------------------------------\n");
	printf("-------------------------------------------\n");
}

void Print::printTcpApp(IPHeader *ip, TCPHeader *tcp, const char *appHeader) {
	SOCKADDR_IN source, dest;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ip->getSrcaddr();

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = ip->getDesaddr();
	printf("프로토콜: %s\n", appHeader);
	printf("출발지 주소: %s\n", strdup(inet_ntoa(source.sin_addr)));
	printf("목적지 주소: %s\n", strdup(inet_ntoa(dest.sin_addr)));
	printf("출발Port/TTL: %u\n", ntohs(tcp->getSrcPort()));
	printf("목적Port: %u\n", ntohs(tcp->getDesPort()));
	printf("-------------------------------------------\n");
	printf("-------------------------------------------\n");
}

void Print::printUdpApp(IPHeader *ip, UDPHeader *udp, const char *appHeader) {
	SOCKADDR_IN source, dest;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ip->getSrcaddr();

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = ip->getDesaddr();
	printf("프로토콜: %s\n", appHeader);
	printf("출발지 주소: %s\n", strdup(inet_ntoa(source.sin_addr)));
	printf("목적지 주소: %s\n", strdup(inet_ntoa(dest.sin_addr)));
	printf("출발Port/TTL: %u\n", ntohs(udp->getSrcPort()));
	printf("목적Port: %u\n", ntohs(udp->getDesPort()));
	printf("-------------------------------------------\n");
	printf("-------------------------------------------\n");
}
void Print::printMain() {
	printf("-------------------------------------------\n");
	printf("-------------------------------------------\n");
}

void Print::printIcmp(IPHeader *ip, ICMPHeader *icmp) {
	SOCKADDR_IN source, dest;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ip->getSrcaddr();

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = ip->getDesaddr();
	printf("ICMP		%s		%s		%d\n", strdup(inet_ntoa(source.sin_addr)), strdup(inet_ntoa(dest.sin_addr)), (unsigned int)ip->getTTL());
}