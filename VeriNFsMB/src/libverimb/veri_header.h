#ifndef VERIHEADER_H
#define VERIHEADER_H

#include <string>
#include <vector>
#include <unordered_map>
#include <click/config.h>
#include <click/packet.hh>



struct VeriHeader
{
//#if CLICK_BYTE_ORDER == CLICK_BIG_ENDIAN
//	unsigned copied : 1;            /* 20 Set to 1 if the options need to be copied into all fragments of a fragmented packet. */
//	unsigned option_class : 2;      /* Option Class */
//	unsigned option_number : 5;     /* Option Number: specified an option */
//#elif CLICK_BYTE_ORDER == CLICK_LITTLE_ENDIAN
//	unsigned option_number : 5;
//	unsigned option_class : 2;
//	unsigned copied : 1;
//#else
//#   error "unknown byte order"
//#endif
//#define IP_OPCT_COPIED  1         /* copied flag */
//#define IP_OPCT_RINGER  3         /* option class for ringer scheme */
//#define IP_OPNM_RINGER  31        /* option number for ringer scheme */
//
//	uint8_t  op_length;             /* 21 Option Length - the size of the entire option */
//#define IP_OP_LENGTH_RINGER 8     /* entire option field for ringer scheme has 8 octects */
//
	//static const uint16_t veri_option_head_value = 8 << 8 | 31 << 3 | 2 << 1 | 1;
	static const uint16_t veri_option_head_value = 8<<8|1<<7|3<<5|31;

	VeriHeader()
	{
		optionHeader = veri_option_head_value;
		batchID = flowID = cNum = 0;
	}

	uint16_t optionHeader;
	uint16_t batchID;
	uint16_t flowID;
	uint16_t cNum;
};

struct R1
{
	R1()
	{
		batchID = pktID = isDrop = 0;
		*(uint64_t*)timeIn = 0;
		*((uint64_t*)timeIn +1)= 0;
	}

	uint32_t batchID;
	uint64_t pktID;
	uint32_t isDrop;
	char timeIn[16];
};

struct R2
{
	R2() :batchID(0), pktID(0) 
	{
		batchID = pktID = 0;
		*(uint64_t*)timeOut = 0;
		*((uint64_t*)timeOut + 1) = 0;
	}

	uint32_t batchID;
	uint64_t pktID;
	char timeOut[16];
};

struct pktFlow
{
	pktFlow() 
	{
		batchID = flowID = packetCount = 0;
	}

	uint32_t batchID;
	uint32_t flowID;
	uint32_t packetCount;

	//uint8_t protocol;
	//uint32_t srcIP;
	//uint32_t dstIP;
	//uint16_t srcPort;
	//uint16_t dstPort;
};



enum veriType
{
	pktBasedVerify,
	flowBasedVerify
};

enum boxType
{
	LB,
	FW,
	IDS
};

struct veriInfoPkt_t
{
	uint32_t pktID;
	uint16_t fieldID;
	uint16_t ruleID;
};

union veriInfoPkt
{
	veriInfoPkt(uint64_t num = 0) { veriNum = num; }
	veriInfoPkt_t veriData;
	uint64_t veriNum;
};

struct veriInfo
{
	veriInfo():pktCount(0), veriRes(0){}
	int pktCount;
	veriInfoPkt veriRes;
};

//struct batchCounter
//{
//	batchCounter() :dropCount(0), totalTime(0) {}
//	uint32_t batchID;
//	uint32_t flowCount;
//	uint32_t pktCount;
//	uint32_t dropCount;
//	uint32_t totalTime;
//	double avgPkgTime;
//	uint32_t rootTime;
//};

struct gatewayBatch
{
	// init by function
	uint32_t batchID;
	uint32_t batchSize;
	uint32_t flowCount;
	uint32_t packetCount;
	// this equal "total pkt count" add expect "root pkt count"
	uint32_t batchResultPktCount;

	//batchCounter counter;

	std::vector<pktFlow> flows;

	std::vector<R1> r1s;
	std::vector<R2> r2s;

	std::vector<veriInfo> veriPktLB;
	std::string rootPktLB;

	std::unordered_map<std::string, veriInfo> veriFlowLB;
	std::string rootFlowLB;

	std::unordered_map<std::string, veriInfo> veriFlowFW;
	std::string rootFlowFW;

	std::unordered_map<std::string, veriInfo> veriFlowIDS;
	std::string rootFlowIDS;
};

#include "merkle_tree.h"

struct boxBatch
{
	// init by function
	uint32_t batchID;
	veriType typeV;
	boxType typeB;

	uint32_t batchSize;
	uint32_t batchPktSize;
	uint32_t packetCount;

	uint8_t rootPacket[1600];
	bool readyToSendRoot;
	MerkleTree tree;

	// flowid -- pktFlow
	std::unordered_map<uint32_t, pktFlow> flows;

	// pktID or flowid -- veriResult
	std::unordered_map<uint64_t, veriInfo> veriRes;
};


struct elementCounter
{
	elementCounter() 
	{
		useTime = no = pktCount = pktSize = pktPageloadSize= 0;
	}
	uint32_t no;
	double useTime;
	uint32_t pktCount;
	uint32_t pktSize;
	uint32_t pktPageloadSize;
};

struct pktCounter
{
	pktCounter()
	{
		processTime = delay = timestamp = batchID = flowID = cNum = pktLength = pageloadLength = 0;
	}

	uint32_t batchID;
	uint32_t flowID;
	uint32_t cNum;

	uint32_t pktLength;
	uint32_t pageloadLength;

	double processTime;
	double delay;
	double timestamp;
};

struct fwRule
{
	fwRule() 
	{
		//minSrcIP = maxSrcIP = minDstIP = maxDstIP = 0;
		ip = 0;
	}

	bool isSrc;
	uint32_t ip;
	//uint32_t minSrcIP;
	//uint32_t maxSrcIP;
	//uint32_t minDstIP;
	//uint32_t maxDstIP;
};


#include <cryptopp/hex.h>
#include <cryptopp/randpool.h>
#include <cryptopp/sha.h>

class encTools
{
public:
	static const int SHA256_len = 32;

	static std::string SHA256(uint8_t* data, int len);
	static std::string SHA256(const std::string& data);

	// return a string saved timespec
	static std::string timeNow();
	static double differTimeInNsec(const char * const begin, const char * const end);



	template< typename K, typename V>
	static std::vector<V> map2vec(const std::unordered_map<K, V>& map)
	{
		std::vector<V> ret;
		for (auto it = map.begin(); it != map.end(); it++)
		{
			ret.push_back(it->second);
		}
		return ret;
	}
};


#endif