#ifndef CLICK_VERITOOLS_HH
#define CLICK_VERITOOLS_HH

#include <click/config.h>
#include <click/element.hh>
#include <string>
#include <tuple>
#include <fstream>

#include "../libverimb/veri_header.h"
#include "../libverimb/pkt_reader.h"
#include "element_config.h"
#include "../libverimb/pattern_loader.h"
#include "../libverimb/dfc/dfc_adaptor.h"
#include "../libverimb/ac/ac_adaptor.h"


CLICK_DECLS

// need server config file
class VeriTools : public Element {
public:
	VeriTools() CLICK_COLD;

	const char *class_name() const { return "VeriTools"; }
	const char *port_count() const { return PORTS_1_1; }
	const char *processing() const { return "h/l"; }

	static bool isTestPacket(Packet* p);
	static void showPacket(Packet* p);
	static uint32_t getPktID(uint16_t flowID, uint16_t cNum);
	static std::tuple<uint16_t, uint16_t> divideID(uint32_t pktID);
	static WritablePacket* reDirectionPacket(WritablePacket* pkt_in, const char* srcIP, const char* srcMac, const char* dstIP, const char* dstMac);
	static Packet* mkDummpPacket(Packet* pkt_in);
	static std::string fiveTuple(Packet* pkt_in);
	static std::string fiveTuple(pktFlow& flow);
	static bool isSample(Packet* ip,    double prop = 1);	//0.034
	static bool isSample(pktFlow& flow, double prop = 1);	//0.034

	static void setPacketMate(Packet * p, uint32_t cNum, std::string & flowmate);
	static bool initFW();
	static bool checkRule(uint32_t srcIP, uint32_t dstIP, const fwRule& rule);
	static bool initIDS(PMAdaptor** engine, PatternSet& pattern);
	static std::string patternMatching(PMAdaptor* engine, unsigned char* data, uint32_t len);

	static std::string sha5tup(Packet* pkt_in);
	// len is bit length, max is 64
	static uint64_t sha5tup(Packet* pkt_in, int len);
	static std::string sha5tup(pktFlow& flow);
	// len is bit length, max is 64
	static uint64_t sha5tup(pktFlow& flow, int len);

	static void initBoxBatch(boxBatch& batch, uint32_t id, veriType v, boxType b);
	static void initFlow(pktFlow& flow, uint32_t batchID, uint32_t flowID);

	static bool buildVeriTree(boxBatch& batch);
	static WritablePacket* makeUDPPacket();
	
	//static void genPackets(char* fileName, int pktCount, int flowSize, int pageloadSize);
	
	// return new 32bit ip
	static uint32_t processLB(Packet* p_in);
	static uint64_t updateFlowVeri(veriInfo& flow_veri, const veriInfoPkt& pktVeriResult, Packet* p_in);

	static uint64_t fflowLB (Packet* p_in);
	static uint64_t fflowFW (Packet* p_in);
	static uint64_t fflowIDS(Packet* p_in);

	static std::string setPktCounter(pktCounter& counter, Packet* p_ref);
	static std::string formatPktCounter(const pktCounter& counter);
	static std::string formatElementCounter(const elementCounter& counter);

	static int getVeriRandom(Packet* p_in);

	static void checkElementCounter(elementCounter & counter, std::string & preTime, std::vector<std::string>& eleContainer);
};

CLICK_ENDDECLS
#endif
