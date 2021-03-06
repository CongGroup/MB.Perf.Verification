#ifndef CLICK_MIDDLEBOXLB_HH
#define CLICK_MIDDLEBOXLB_HH
#include <click/element.hh>
#include <deque>
#include <unordered_map>
#include "veritools.hh"

CLICK_DECLS

// need server config file
class MiddleboxLB : public Element {
public:
	MiddleboxLB() CLICK_COLD;

	const char *class_name() const { return "MiddleboxLB"; }
	const char *port_count() const { return PORTS_1_1; }
	const char *processing() const { return PUSH_TO_PULL; }

	int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
	bool can_live_reconfigure() const { return true; }

	int initialize(ErrorHandler *errh);

	void push(int port, Packet *p);
	Packet* pull(int port);

protected:
	int validTotalPkgCount;

	int readyToSendRoot;
	std::string preTime;
	std::string startTime;
	elementCounter boxCounter;
	std::ofstream boxLogger;
	std::ofstream pktLogger;

	std::vector<std::string> eleContainer;
	std::vector<std::string> pktContainer;

	void buildTreeAndSendRootPkt(boxBatch& batch);

	std::unordered_map<uint32_t, boxBatch> batches;

	std::deque<Packet*> ready_packet;

	double boxTotalTime;
	std::string activityTime;
};

CLICK_ENDDECLS
#endif
