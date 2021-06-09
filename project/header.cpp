#include "header.h"

IPHeader::IPHeader() {}
IPHeader::IPHeader(char *packet) {
	this->header = (IPV4H *)packet;
}

unsigned int IPHeader::getDesaddr() {
	return this->header->ipDestaddr;
}

unsigned int IPHeader::getSrcaddr() {
	return this->header->ipSrcaddr;
}

unsigned char IPHeader::getProtocol() {
	return this->header->ipProtocol;
}

unsigned short IPHeader::getIpLength() {
	return this->header->ipHeaderLength;
}

unsigned char IPHeader::getIpVer() {
	return this->header->ipVer;
}
unsigned char IPHeader::getIpTos() {
	return this->header->ipTos;
}

unsigned short IPHeader::getIpChecksum() {
	return this->header->ipChecksum;
}
unsigned char IPHeader::getIpHLen() {
	return this->header->ipHeaderLength;
}

unsigned short IPHeader::getIpId() {
	return this->header->ipId;
}

unsigned char IPHeader::getTTL() {
	return this->header->ipTTL;
}

TCPHeader::TCPHeader(int ipSize, char *packet) {
	this->header = (TCPH*)(packet + ipSize);
}

unsigned short TCPHeader::getDesPort() {
	return this->header->destPort;
}

unsigned short TCPHeader::getSrcPort() {
	return this->header->sourcePort;
}

unsigned char TCPHeader::getTcpLength() {
	return this->header->dataOffset;
}

unsigned int TCPHeader::getSeqNo() {
	return this->header->sequence;
}

unsigned int TCPHeader::getAckNo() {
	return this->header->acknowledge;
}

unsigned char TCPHeader::getUrg() {
	return this->header->urg;
}

unsigned char TCPHeader::getAck() {
	return this->header->ack;
}

unsigned char TCPHeader::getPush() {
	return this->header->psh;
}

unsigned char TCPHeader::getRes() {
	return this->header->rst;
}

unsigned char TCPHeader::getSyn() {
	return this->header->syn;
}

unsigned char TCPHeader::getFin() {
	return this->header->fin;
}
unsigned short TCPHeader::getWin() {
	return this->header->window;
}

unsigned short TCPHeader::getChecksum() {
	return this->header->checksum;
}

unsigned short TCPHeader::getUrgPointer() {
	return this->header->urgentPointer;
}

UDPHeader::UDPHeader(int ipSize, char *packet) {
	this->header = (UDPH*)(packet + ipSize);
}

unsigned short UDPHeader::getDesPort() {
	return this->header->destPort;
}

unsigned short UDPHeader::getSrcPort() {
	return this->header->sourcePort;
}

unsigned short UDPHeader::getUdpLength() {
	return this->header->udpLength;
}

unsigned short UDPHeader::getUdpChecksum() {
	return this->header->udpChecksum;
}
DNSHeader::DNSHeader() {}
DNSHeader::DNSHeader(int headerSize, char *packet)
{
	this->header = (DNSH*)(packet + headerSize);
}
unsigned short  DNSHeader::getQCount() {
	return this->header->qCount;
}

unsigned short  DNSHeader::getAnsCount() {
	return this->header->ansCount;
}

unsigned short  DNSHeader::getAuthCount() {
	return this->header->authCount;
}

unsigned short  DNSHeader::getAddCount() {
	return this->header->addCount;
}

ICMPHeader::ICMPHeader(int ipSize, char *packet) {
	this->header = (ICMPH*)(packet + ipSize);
}

unsigned short ICMPHeader::getType() {
	return this->header->icmp_type;
}

unsigned short ICMPHeader::getCode() {
	return this->header->icmp_code;
}

unsigned short ICMPHeader::getChecksum() {
	return this->header->icmp_checksum;
}