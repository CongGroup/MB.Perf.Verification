#ifndef CLICK_GATEWAYSENDER_HH
#define CLICK_GATEWAYSENDER_HH
#include <click/element.hh>
#include <deque>
#include <unordered_map>
#include <vector>
#include "../libverimb/pkt_reader.h"

#include "veritools.hh"

CLICK_DECLS

// need server config file
class GatewaySender : public Element {
public:
	GatewaySender() CLICK_COLD;
	~GatewaySender() CLICK_COLD;

	const char *class_name() const { return "GatewaySender"; }
	const char *port_count() const { return "1-2/1"; }
	const char *processing() const { return PUSH_TO_PULL; }

	int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
	bool can_live_reconfigure() const { return true; }

	int initialize(ErrorHandler *errh);

	void push(int port, Packet *p);
	Packet* pull(int port);

	

protected:
	uint32_t gatewayTimer;
	uint32_t gatewayInputSize;
	uint32_t gatewayOutputSize;

	// storage all batch
	std::vector<gatewayBatch> batches;

	// key is 5-tuple
	std::unordered_map<std::string, pktFlow> flowFilter;
	// key is verHeader
	std::unordered_map<std::string, pktFlow> allFlows;
	// key is verHeader
	std::unordered_map<std::string, int> five_tuple_loolup_table;

	std::string startTime1;
	std::string startTime2;
	std::string preTime1;
	std::string preTime2;
	elementCounter gateway1Counter;
	elementCounter gateway2Counter;

	std::vector<std::string> ele1Container;
	std::vector<std::string> ele2Container;
	std::vector<std::string> pkt1Container;
	std::vector<std::string> pkt2Container;

	std::ofstream gateway1Logger;
	std::ofstream gateway2Logger;
	std::ofstream pkt1Logger;
	std::ofstream pkt2Logger;

	// deque to sen pkt
	std::deque<Packet*> ready_packet;
	

	void initBatch(gatewayBatch& batch);
	WritablePacket* addVeriHeader(Packet* pkt_in);	

	// make a pkt to notice box batch real pkt count
	WritablePacket* makeSpecialPkt(Packet* pkt_ref, int batchCount);

	//double checkBatchTime(gatewayBatch& pkt);

	uint32_t totalPktCount;
	uint32_t validTotalPkgCount;

	double totalGateway1Time;
	double totalGateway2Time;

	unsigned char** pktCache;
	std::string activityTime;
};

CLICK_ENDDECLS
#endif
