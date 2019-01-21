#include "veritools.hh"

#include <cmath>
#include <clicknet/ip.h>
#include <clicknet/udp.h>
#include <clicknet/ether.h>
#include <sstream>
#include <stdlib.h>

#include <arpa/inet.h>

#include "../libverimb/SimConHash.h"

CLICK_DECLS

using namespace std;

VeriTools::VeriTools()
{
}


bool VeriTools::isTestPacket(Packet * p)
{
	//static const in_addr_t srcAddr(inet_addr("192.168.1.2"));
	//return (memcmp(PACKET_DATA_OFFSET(p, void*, ether_len+12), &srcAddr, sizeof(in_addr_t))==0);
	return PktReader(p).getIPHeaderLength() == ip_default_len + sizeof(VeriHeader);
}

void VeriTools::showPacket(Packet * p)
{
	const int ip_header_offset = ether_len;

	const int package_real_size = p->length();

	const click_ip * pcip = PACKET_DATA_OFFSET(p, click_ip*, ip_header_offset);

	const uint8_t version = (*PACKET_DATA_OFFSET(p, uint8_t*, ip_header_offset)) >> 4;

	// ip head length
	const uint8_t head_len = ((*PACKET_DATA_OFFSET(p, uint8_t*, ip_header_offset)) & 0xf) * 4;

	uint32_t batchID = 0;
	uint32_t flowID = 0;
	uint32_t cNum= 0;
	if (head_len == ip_default_len + sizeof(VeriHeader))
	{
		VeriHeader * pVeri = PACKET_DATA_OFFSET(p, VeriHeader *, ip_header_offset + ip_default_len) ;
		batchID = pVeri->batchID;
		flowID = pVeri->flowID;
		cNum = pVeri->cNum;
	}

	uint16_t ip_length = *PACKET_DATA_OFFSET(p, uint16_t*, ip_header_offset + 2);
	ip_length = ntohs(ip_length);

	const uint16_t ip_id = ntohs(*PACKET_DATA_OFFSET(p, uint16_t*, ip_header_offset + 4));

	const bool is_MF = *PACKET_DATA_OFFSET(p, uint8_t*, ip_header_offset + 6) >> 5 & 0x1;
	const bool is_DF = *PACKET_DATA_OFFSET(p, uint8_t*, ip_header_offset + 6) >> 6 & 0x1;
	const uint16_t fragment_offset = ntohs(*PACKET_DATA_OFFSET(p, uint16_t*, ip_header_offset + 6)) & 0x1FFF;

	const struct in_addr src_ip = *PACKET_DATA_OFFSET(p, in_addr*, ip_header_offset + 12);
	const struct in_addr dst_ip = *PACKET_DATA_OFFSET(p, in_addr*, ip_header_offset + 16);

	const char* ip_src_str = strdup(inet_ntoa(src_ip));
	const char* ip_dst_str = strdup(inet_ntoa(dst_ip));

	const uint8_t protocol = *PACKET_DATA_OFFSET(p, uint8_t*, ip_header_offset + 9);
	uint8_t* pdata = PACKET_DATA_OFFSET(p, uint8_t*, ip_header_offset + head_len);

	if (protocol == IP_PROTO_TCP || protocol == IP_PROTO_UDP)
	{
		uint16_t src_port = *PACKET_DATA_OFFSET(p, uint16_t*, ether_len + head_len);
		src_port = ntohs(src_port);
		uint16_t dst_port = *PACKET_DATA_OFFSET(p, uint16_t*, ether_len + head_len + sizeof(uint16_t));
		dst_port = ntohs(dst_port);

		//udp header is 8 
		uint16_t data_length = ip_length - head_len - udp_default_len;
		pdata += udp_default_len;
		if (protocol == IP_PROTO_TCP)
		{
			uint8_t data_offset = *PACKET_DATA_OFFSET(p, uint8_t*, ether_len + head_len + 12);
			data_offset *= 4;
			data_length -= (data_offset - udp_default_len);
			pdata += (data_offset - udp_default_len);
		}
		click_chatter("IP version %d, header-len is %d, ip-len is %d, package-len is %d.\n", version, head_len, ip_length, package_real_size);
		click_chatter("  ID is %d, MF is %d, DF is %d, offset is %d. \n", ip_id, is_MF, is_DF, fragment_offset);
		if (head_len == ip_default_len + sizeof(VeriHeader))
		{
			click_chatter("  veriHeader: bat:%d, flow:%d, cNum:%d.\n", batchID, flowID, cNum);
		}
		click_chatter("  %s, %s:%d to %s:%d, data_len is %d, data begin with %.2X\n", protocol == IP_PROTO_TCP ? "TCP" : "UDP",
			ip_src_str, src_port, ip_dst_str, dst_port, data_length, *pdata);
	}
	else
	{
		click_chatter("##########Unknown protocol, protocol id is %d.\n", protocol);
	}
}

uint32_t VeriTools::getPktID(uint16_t flowID, uint16_t cNum)
{
	return ((uint16_t)flowID) << 16 | cNum;
}

tuple<uint16_t, uint16_t> VeriTools::divideID(uint32_t pktID)
{
	return std::make_tuple<uint32_t, uint32_t>(pktID>>16, pktID&0xffff);
}

static uint8_t* dataMac(const char* strMac, const int strLeng)
{
	static uint8_t dstMac[12];
	for (int i = 0, j = 0; i < strLeng; i++)
	{
		char c = strMac[i];
		if (c >= 48 && c <= 57)
		{
			dstMac[j++] = c - 48;
		}
		else if (c >= 65 && c <= 70)
		{
			dstMac[j++] = c - 55;
		}
		else if (c >= 97 && c <= 102)
		{
			dstMac[j++] = c - 87;
		}
		else
		{
			continue;
		}
	}
	for (int i = 0; i < 6; i++)
	{
		dstMac[i] = (dstMac[i * 2] << 4) | (dstMac[i * 2 + 1]);
	}

	return dstMac;
}

WritablePacket * VeriTools::reDirectionPacket(WritablePacket * pkt_in, const char* srcIP, const char* srcMac, const char* dstIP, const char* dstMac)
{
	const static int MaxPageLoadLength = ether_max_size - ether_len - ip_default_len - sizeof(VeriHeader) - udp_default_len;
	
	PktReader reader(pkt_in);
	int pageLoadLen = reader.getDataLength();
	if (pageLoadLen > MaxPageLoadLength)
	{
		pageLoadLen = MaxPageLoadLength;
	}

	const int headerLen = reader.getIPHeaderLength();
	const int pktHaveLen = pkt_in->length() - ether_len - headerLen - udp_default_len;
	if (pageLoadLen > pktHaveLen)
	{
		pageLoadLen = pktHaveLen;
	}


	click_udp* udp = (click_udp*)(reader.getData());
	udp->uh_sport = host_to_net_order(srcPort);
	udp->uh_dport = host_to_net_order(dstPost);
	udp->uh_ulen = host_to_net_order(uint16_t(udp_default_len + pageLoadLen));
	udp->uh_sum = 0; // not used in IPv4

	click_ip* ip = (click_ip*)reader.getIPHeader();
	/* swap source and destionation addresses */
	ip->ip_p = IPPROTO_UDP;
	ip->ip_src.s_addr = inet_addr(srcIP);
	ip->ip_dst.s_addr = inet_addr(dstIP);
	ip->ip_len = host_to_net_order(uint16_t(headerLen + udp_default_len + pageLoadLen));
	ip->ip_sum = 0;
	ip->ip_sum = click_in_cksum((const unsigned char*)ip, headerLen);

	click_ether* ether = (click_ether*)pkt_in->data();
	//ether->ether_type = ETHERTYPE_IP;
	memcpy(&ether->ether_shost[0], dataMac(srcMac, strlen(srcMac)), 6);
	if (isAzure)
	{
		memcpy(&ether->ether_dhost[0], dataMac(azureDstMac, strlen(azureDstMac)), 6);
	}
	else
	{
		memcpy(&ether->ether_dhost[0], dataMac(dstMac, strlen(dstMac)), 6);
	}

	int pktLength = ether_len + headerLen + udp_default_len + pageLoadLen;


	if (pkt_in->length() > pktLength)
	{
		pkt_in->take(pkt_in->length() - pktLength);
	}
	//click_chatter("after take pktLen is %d, should be %d.\n", pkt_in->length(), pktLength);
	
	return pkt_in;
}

Packet * VeriTools::mkDummpPacket(Packet * pkt_in)
{
	return nullptr;
}


std::string VeriTools::fiveTuple(Packet * pkt_in)
{
	// actually this func need FIVE tuple, but for exp. we use veri info 
	// because the ip and port need modify to send packet to next packet

	PktReader reader(pkt_in);
	if (reader.getIPHeaderLength() == ip_default_len + sizeof(VeriHeader))
	{
		VeriHeader* pveri = (VeriHeader*)reader.getIpOption();
		return string().append((char*)&pveri->batchID, sizeof(pveri->batchID))
			.append((char*)&pveri->flowID, sizeof(pveri->flowID));
	}
	else if (reader.getIPHeaderLength() == ip_default_len)
	{
		return string().append(to_string(reader.getProtocol()))
			.append(inet_ntoa(reader.getSrcIP()))
			.append(inet_ntoa(reader.getDstIP()))
			.append(to_string(reader.getSrcPort()))
			.append(to_string(reader.getDstPort()));
	}
	else
	{
		click_chatter("ip header length error (5tuple)");
	}
}

std::string VeriTools::fiveTuple(pktFlow & flow)
{
	// actually this func need FIVE tuple, but for exp. we use veri info 
	// because the dstIP and port need modify to send packet to next packet

	//if(!bothway)
	return std::string().append((char*)&flow.batchID, sizeof(flow.batchID))
		.append((char*)&flow.flowID, sizeof(flow.flowID));
	//else
	//{
	//	pktFlow temp(flow);

	//	return std::string().append((char*)&temp.batchID, sizeof(temp.batchID))
	//		.append((char*)&temp.flowID, sizeof(temp.flowID));
	//}

	// return std::string().append(to_string(flow.protocol))
	//	.append(inet_ntoa(srcAddr))
	//	.append(inet_ntoa(dstAddr))
	//	.append(to_string(flow.srcPort))
	//	.append(to_string(flow.dstPort));
}

bool VeriTools::isSample(Packet * ip, double prop)
{
	return (sha5tup(ip, 16) <= prop * 0xffff) ? true : false;
}

bool VeriTools::isSample(pktFlow & flow, double prop)
{
	return (sha5tup(flow, 16) <= prop * 0xffff) ? true : false;
}

//void VeriTools::addPacketMateToFlow(Packet * p, uint32_t cNum, pktFlow & flow)
//{
//	char c = 0;
//	if (cNum % 8 != 1)
//	{
//		c = flow.mateData.at(flow.mateData.length() - 1);
//		c <<= 1;
//	}
//
//	PktReader reader(p);
//	c |= ((*(reader.getData() + (cNum - 1) / 8 % reader.getDataLength()) >> ((cNum - 1) % 8)) & 1);
//
//	if (cNum % 8 != 1)
//	{
//		flow.mateData.erase(flow.mateData.end() - 1);
//	}
//	flow.mateData.append(1, c);
//
//}
//
void VeriTools::setPacketMate(Packet * p, uint32_t cNum, std::string & flowmate)
{
	//PktReader reader(p);
	//if (flowmate.length() < (cNum - 1) / 8 + 1)
	//{
	//	flowmate.append((cNum - 1) / 8 + 1, '0');
	//}
	//char c = flowmate.at((cNum - 1)/8);
	//c |= ((*(reader.getData() + (cNum - 1) / 8 % reader.getDataLength())) & (1 << ((cNum - 1) % 8)));
	//flowmate.replace((cNum - 1) / 8, 1, 1, c);
	//flowmate.replace((cNum - 1) / 8, 1, 1, *(p->data()));
	if (flowmate.length() < cNum)
	{
		flowmate.append(cNum, '0');
	}
	flowmate.replace(cNum, 1, 1, *(p->data()));
}

bool VeriTools::initFW()
{
	// TODO: move middlebox firewall init to this function
	return false;
}

bool VeriTools::checkRule(uint32_t srcIP, uint32_t dstIP, const fwRule& rule)
{
	if (rule.isSrc)
	{
		return srcIP == rule.ip;
	}
	else
	{
		return dstIP == rule.ip;
	}
}

bool VeriTools::initIDS(PMAdaptor ** engine, PatternSet & pattern)
{
	PatternLoader::load_pattern_file(patternFilePath, pattern);
	if (idsEngineIsAC)
	{
		*engine = new ACAdaptor();
	}
	else
	{
		*engine = new DFCAdaptor();
	}
	(*engine)->init(pattern);

	return true;
}

std::string VeriTools::patternMatching(PMAdaptor * engine, unsigned char * data, uint32_t len)
{
	std::string res; 
	engine->process(0, data, len, res);
	return res;
}


string VeriTools::sha5tup(Packet * pkt_in)
{
	return encTools::SHA256(fiveTuple(pkt_in));
}

uint64_t VeriTools::sha5tup(Packet * pkt_in, int len)
{
	uint64_t beginWithInteger = 0;
	memcpy(&beginWithInteger, sha5tup(pkt_in).data(), len/8);
	return beginWithInteger;
}

std::string VeriTools::sha5tup(pktFlow & flow)
{
	return encTools::SHA256(fiveTuple(flow));
}

uint64_t VeriTools::sha5tup(pktFlow & flow, int len)
{
	uint64_t beginWithInteger = 0;
	memcpy(&beginWithInteger, sha5tup(flow).data(), len / 8);
	return beginWithInteger;
}

void VeriTools::initBoxBatch(boxBatch & batch, uint32_t id, veriType v, boxType b)
{
	const int batch_element_size = 1024;
	batch.batchID = id;
	batch.batchSize = batch_element_size;
	batch.typeV = v;
	batch.typeB = b;
	batch.packetCount = 0;
	batch.batchPktSize = (v == flowBasedVerify? 0xffff: batch_element_size);
	batch.readyToSendRoot = false; 
	batch.flows.reserve(batch_element_size);
	batch.veriRes.reserve(batch_element_size);

	memset(batch.rootPacket, 0, sizeof(batch.rootPacket));
}

void VeriTools::initFlow(pktFlow& flow, uint32_t batchID, uint32_t flowID)
{
	flow.packetCount = 0;
	flow.batchID = batchID;
	flow.flowID = flowID;
	//PktReader r(p_init);
	//flow.protocol = r.getProtocol();
	//in_addr addr = r.getSrcIP();
	//memcpy(&flow.srcIP, &addr, sizeof(flow.srcIP));
	//addr = r.getDstIP();
	//memcpy(&flow.dstIP, &addr, sizeof(flow.dstIP));
	//flow.srcPort = r.getSrcPort();
	//flow.dstPort = r.getDstPort();
}

bool VeriTools::buildVeriTree(boxBatch & batch)
{
	std::unordered_map<uint64_t, veriInfo>& veris = batch.veriRes;

	size_t leavesCount = veris.size();

	if ((leavesCount & leavesCount - 1) != 0)
	{
		click_chatter("leavesCount is %d, build tree failed.\n", leavesCount);
		return false;
	}

	std::vector<std::string> res;
	for (auto it = veris.begin(); it != veris.end(); it++)
	{
		res.push_back(std::string((char*)&it->second.veriRes, sizeof(it->second.veriRes)));
	}

	// 8 packets tree`s height is 4
	int height = floor(log(leavesCount) / log(2) + 0.5) + 1;

	batch.tree.buildtree(height, res);
	return true;
}

WritablePacket * VeriTools::makeUDPPacket()
{
	const int mtu = 1500;
	static bool initFlag = false;
	static unsigned char pkt_buffer[ether_max_size];

	if (!initFlag)
	{
		const bool haveVeriHeader = true;

		memset(pkt_buffer, 0, ether_max_size);

		click_ether* pether = (click_ether*)pkt_buffer;
		pether->ether_type = htons(ETHERTYPE_IP);

		click_ip* pcip = (click_ip*)(pkt_buffer + ether_len);
		pcip->ip_v = 4;
		uint8_t ipHeaderLen = haveVeriHeader ? ip_default_len+sizeof(VeriHeader) : ip_default_len;
		pcip->ip_hl = ipHeaderLen / 4;
		pcip->ip_tos = IP_ECN_NOT_ECT;
		pcip->ip_len = htons(mtu);
		pcip->ip_id = 0;
		pcip->ip_off = htons(IP_DF);
		pcip->ip_ttl = 64;
		pcip->ip_p = IPPROTO_UDP;

		if (haveVeriHeader)
		{
			VeriHeader header;
			VeriHeader* pheader = (VeriHeader*)(pkt_buffer + ether_len + ip_default_len);
			*pheader = header;
		}

		click_udp* udp = (click_udp*)(pkt_buffer + ether_len + ipHeaderLen);
		udp->uh_ulen = htons(uint16_t(mtu - ipHeaderLen));

		initFlag = true;
	}
	
	WritablePacket* p = Packet::make(pkt_buffer, ether_max_size);

	return p;
}

uint32_t VeriTools::processLB(Packet * p_in)
{
	static bool initHash = false;
	static SimConHash<uint32_t> hash;
	if (!initHash)
	{
		const uint32_t uiMax = (uint32_t)-1;
		const int serverCount = 20;
		uint32_t uiInterval = uiMax / serverCount - serverCount;

		for (uint32_t uiCur = 0; uiCur < serverCount; uiCur++)
		{
			hash.InsertNode(uiInterval * (uiCur + 1), uiInterval * (uiCur + 1));
		}
		initHash = true;
	}
	return *hash.Query((uint32_t)sha5tup(p_in, 32));
}

uint64_t VeriTools::updateFlowVeri(veriInfo & flow_veri, const veriInfoPkt & pktVeriResult, Packet* p_in)
{
	flow_veri.pktCount += 1;
	flow_veri.veriRes.veriNum *= getVeriRandom(p_in);
	flow_veri.veriRes.veriNum += pktVeriResult.veriNum;
	return flow_veri.veriRes.veriNum;
}

uint64_t veriPkt(Packet* p_in, uint16_t fidleID, uint16_t ruleID)
{
	VeriHeader* pVeri = (VeriHeader*)PktReader(p_in).getIpOption();
	veriInfoPkt veri;
	veri.veriData.pktID = VeriTools::getPktID(pVeri->flowID, pVeri->cNum);
	veri.veriData.fieldID = fidleID;
	veri.veriData.ruleID = ruleID;
	return veri.veriNum;
}

// flowID layer(3) ruleid(0) output(dstIP) pktMate
uint64_t VeriTools::fflowLB(Packet* p_in)
{
	return veriPkt(p_in, 3, 0);
}

// flowID layer(4) ruleid(0) dropFlag counter
uint64_t VeriTools::fflowFW(Packet* p_in)
{
	return veriPkt(p_in, 4, 0);
}

// flowID layer(7) ruleID(0)  mate(pageload-length)
uint64_t VeriTools::fflowIDS(Packet* p_in)
{
	return veriPkt(p_in, 7, 0);
}

std::string VeriTools::setPktCounter(pktCounter & counter, Packet* p_ref)
{
	PktReader reader(p_ref);
	VeriHeader* pveri = (VeriHeader*)reader.getIpOption();
	counter.batchID = pveri->batchID;
	counter.flowID = pveri->flowID;
	counter.cNum = pveri->cNum;
	counter.pktLength = p_ref->length();
	counter.pageloadLength = reader.getDataLength();

	return std::string();
}

std::string VeriTools::formatPktCounter(const pktCounter & counter)
{
	static const string comma(",");
	stringstream ss;
	ss << "pkt, " << to_string(counter.batchID) << comma << to_string(counter.flowID) << comma
		<< to_string(counter.cNum) << comma << to_string(counter.pktLength) << comma
		<< to_string(counter.pageloadLength) << comma << to_string(counter.processTime) << comma
		<< to_string(counter.delay)<<comma<<to_string(counter.timestamp)<<endl;
	return ss.str();
}

std::string VeriTools::formatElementCounter(const elementCounter & counter)
{
	static const string comma(",");
	stringstream ss;
	ss << "element, " << to_string(counter.no) << comma << to_string(counter.useTime) << comma
		<< to_string(counter.pktCount) << comma << to_string(counter.pktSize) << comma
		<< to_string(counter.pktPageloadSize)<<endl;
	return ss.str();
}

int VeriTools::getVeriRandom(Packet* p_in)
{
	static PktReader reader;
	reader.attach(p_in);
	string res =  encTools::SHA256(reader.getIpOption(), sizeof(VeriHeader));
	return *((int*)res.data());
	//static vector<int> orderRandom;
	//int rNum = orderRandom.size()>0? *orderRandom.rbegin(): randomSeed;
	//while (orderRandom.size() < loc + 1)
	//{
	//	srand(rNum);
	//	rNum = rand();
	//	orderRandom.push_back(rNum);
	//}
	//return orderRandom[loc-1];
}

void VeriTools::checkElementCounter(elementCounter & counter, std::string & preTime, std::vector<std::string>& eleContainer)
{
	counter.useTime += encTools::differTimeInNsec(preTime.data(), encTools::timeNow().data());
	if (counter.useTime >= elementCounterBaseGap)
	{
		string str = VeriTools::formatElementCounter(counter);
		click_chatter("%s", str.data());
		eleContainer.push_back(str);
		counter.no++;
		counter.useTime = 0;
		counter.pktCount = 0;
		counter.pktSize = 0;
		counter.pktPageloadSize = 0;
	}
	preTime = encTools::timeNow();
}

CLICK_ENDDECLS
EXPORT_ELEMENT(VeriTools)
ELEMENT_MT_SAFE(VeriTools)
ELEMENT_LIBS(-lverimb -lcryptopp)
