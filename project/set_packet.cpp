#include "set_packet.h"
#include "packet_print.h"
#include <winsock2.h>
#include <iostream>

Packet::Packet(char *packet, Print *print, int size) {
	ip = new IPHeader(packet);
	int ipLen = ip->getIpLength() * 4;
	int tcpLen;
	int udpLen;
	SOCKADDR_IN source, dest;
	char* test;
	char* test1;

	switch (ip->getProtocol())
	{

	case TCP:
		tcpCheck = true;
		tcp = new TCPHeader(ipLen, packet);
		tcpLen = tcp->getTcpLength() * 4;
		switch (this->getPort(ntohs(tcp->getDesPort()), ntohs(tcp->getSrcPort())))
		{
		case HTTP:

			setTcpPayload(packet, ipLen);
			print->fPrintTcp(ip, tcp);
			print->fPrintPayload(app);
			print->fPrintDump(app, (size - ipLen - tcpLen));
			Print::printTcpApp(ip, tcp, "HTTP");
			break;

		default:
			Print::printTcp(ip, tcp);
			break;
		}
		break;

	case UDP: 
		udpCheck = true;
		udp = new UDPHeader(ipLen, packet);
		udpLen = sizeof(UDPH);
		switch (this->getPort(ntohs(udp->getDesPort()), ntohs(udp->getSrcPort())))
		{
		case DNS:
			dns = new DNSHeader(ipLen + udpLen, packet);
			setUdpPayload(packet, ipLen);
			Print::printUdp(ip, udp);
			print->fPrintUdp(ip, udp);
			print->fPrintDns(dns);
			print->fPrintDump(app, (size - ipLen - udpLen));
			Print::printUdpApp(ip, udp, "DNS");
			break;
		default:
			break;
		}
		break;

	case ICMP:
		icmpCheck = true;
		icmp = new ICMPHeader(ipLen, packet);
		print->printIcmp(ip, icmp);
		break;

	default: 
		break;
	}



}
Packet::~Packet() {
	delete ip;

	if (this->tcpCheck)
		delete tcp;

	if (this->udpCheck)
		delete udp;

	if (this->icmpCheck)
		delete udp;
	delete[] app;
}
char* Packet::getPayload() {
	return this->app;
}
void Packet::setTcpPayload(char *packet, int ipLen) { 

	app = (packet + ipLen + tcp->getTcpLength() * 4);

}
void Packet::setUdpPayload(char *packet, int ipLen) { 

	app = (packet + ipLen + sizeof(UDPH));

}
int Packet::getPort(int dest, int source) {

	if (dest == HTTP || source == HTTP)
		return HTTP;

	if (dest == DNS || source == DNS)
		return DNS;
}
void Packets::add(Packet *temp) {
	this->list.push_back(temp);
}
Packet* Packets::getPacket(int index) {
	return this->list[index];
}