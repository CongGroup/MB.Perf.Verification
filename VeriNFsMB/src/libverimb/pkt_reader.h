#ifndef _PKTREADER_H_
#define _PKTREADER_H_

#include <click/packet.hh>
#include <click/integers.hh>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../element/element_config.h"

class PktReader
{
public:
	PktReader() {
		p = 0; 
		ip_header_offset = ether_len;
	}
	PktReader(Packet* pkg) {
		attach(pkg);
		ip_header_offset = ether_len;
	}

	inline void attach(Packet * pkg) {p = pkg;}
	inline Packet* getPacket() { return p; }

#define PACKET_DATA_OFFSET(p,type,offset) ((p)?((type)((p)->data()+(offset))):0)

	inline uint8_t* getIPHeader() { return PACKET_DATA_OFFSET(p, uint8_t*, ip_header_offset); }
	inline uint8_t getIPVersion() { return  (*PACKET_DATA_OFFSET(p, uint8_t*, ip_header_offset)) >> 4;  };
	inline uint8_t getIPHeaderLength() {return ((*PACKET_DATA_OFFSET(p, uint8_t*, ip_header_offset)) & 0xf) * 4;};
	inline uint16_t getIPTotalLength() { return ntohs(*PACKET_DATA_OFFSET(p, uint16_t*, ip_header_offset + 2)); };
	inline uint16_t getIPID() { return ntohs(*PACKET_DATA_OFFSET(p, uint16_t*, ip_header_offset + 4)); };
	inline bool getMF() { return *PACKET_DATA_OFFSET(p, uint8_t*, ip_header_offset + 6) >> 5 & 0x1; };
	inline bool getDF() { return *PACKET_DATA_OFFSET(p, uint8_t*, ip_header_offset + 6) >> 6 & 0x1; };
	inline uint16_t getFragmentOffset() { return ntohs(*PACKET_DATA_OFFSET(p, uint16_t*, ip_header_offset + 6)) & 0x1FFF; };
	inline struct in_addr getSrcIP() { return *PACKET_DATA_OFFSET(p, in_addr*, ip_header_offset + 12); };
	inline struct in_addr getDstIP() { return *PACKET_DATA_OFFSET(p, in_addr*, ip_header_offset + 16); };
	inline uint8_t* getIpOption() { return PACKET_DATA_OFFSET(p, uint8_t*, ip_header_offset+ ip_default_len);}
	inline uint8_t getProtocol() { return *PACKET_DATA_OFFSET(p, uint8_t*, ip_header_offset + 9); };
	inline uint16_t getSrcPort() { return ntohs(*PACKET_DATA_OFFSET(p, uint16_t*, ip_header_offset + getIPHeaderLength())); };
	inline uint16_t getDstPort() { return ntohs(*PACKET_DATA_OFFSET(p, uint16_t*, ip_header_offset + getIPHeaderLength() + sizeof(uint16_t))); };
	inline uint16_t getDataLength() {return getProtocol() == IP_PROTO_TCP ? (getIPTotalLength() - getIPHeaderLength() - (*PACKET_DATA_OFFSET(p, uint8_t*, ip_header_offset + getIPHeaderLength() + 12) * 4)) : (getIPTotalLength() - getIPHeaderLength() - udp_default_len);};
	inline uint8_t* getData() {return getIPHeader() + getIPHeaderLength();};
private:
	Packet * p;

	int ip_header_offset;
};

#endif
