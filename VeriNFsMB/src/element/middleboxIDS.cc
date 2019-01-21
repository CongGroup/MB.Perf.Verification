#include <click/config.h>
#include <click/args.hh>
#include <click/error.hh>
#include <click/integers.hh>

#include <cmath>
#include <sys/socket.h>
#include "middleboxIDS.hh"
#include "veritools.hh"

CLICK_DECLS

using namespace std;

MiddleboxIDS::MiddleboxIDS()
{
}


static bool veriSwitch = true;
static bool justSend = false;
static bool localMode = false;
static bool bothway = false;
static int  batch_element_size = 1024;
static int  maxPktUsed = 1024 * 10 * 10 + 200;
static bool lbInTheChain = false;
static bool fwInTheChain = false;
static bool idsInTheChain = false;

int
MiddleboxIDS::configure(Vector<String> &conf, ErrorHandler* errh)
{

	//if (Args(conf, errh)
	//	.complete() < 0)
	//{
	//	return -1;
	//}
	// Parsing
	int inChain;
	if (Args(conf, errh)
		//.read_m("PATTERN_FILE", m_config.pattern_file)
		.read_m("BATCH_SIZE", batch_element_size)
		.read_m("EXP_SIZE", maxPktUsed)
		.read_m("VERIFY", veriSwitch)
		.read_m("DISABLE_NETWORK", localMode)
		.read_m("BASELINE", justSend)
		.read_m("QUEYR_TABLE", bothway)
		.read_m("IN_CHAIN", inChain)
		.complete() < 0)
	{
		return -1;
	}

	if (inChain)
	{
		lbInTheChain = true;
		fwInTheChain = true;
		idsInTheChain = true;
	}
	else
	{
		lbInTheChain = false;
		fwInTheChain = false;
		idsInTheChain = false;
	}

	return 0;
}

int MiddleboxIDS::initialize(ErrorHandler *errh)
{
	//char strBuffer[2000];
	//// test sha256
	//const int num[] = {6, 200, 400, 600, 800, 1000, 1200};

	//for (int k = 0; k < sizeof(num) / sizeof(int); k++)
	//{
	//	std::string start = encTools::timeNow();
	//	for (int i = 0; i < 10000; i++)
	//	{
	//		string str;
	//		str.assign(strBuffer, num[k]);
	//		std::string res = encTools::SHA256(str);
	//	}
	//	std::string end = encTools::timeNow();
	//	double t = encTools::differTimeInNsec(start.data(), end.data());

	//	click_chatter("SHA %d  B data need %lf ns.\n", num[k], t);
	//}
	//click_chatter("\n\n\n\n");

	click_chatter("===============================================\n");
	click_chatter("Batch size\t:\t%d\n", batch_element_size);
	click_chatter("Packets count\t:\t%d\n", maxPktUsed);

	click_chatter("Baseline test is %s\n", justSend ? "enable" : "disable");
	click_chatter("Veri function is %s\n", veriSwitch ? "enable" : "disable");
	click_chatter("Local test is %s\n", localMode ? "enable" : "disable");
	click_chatter("Query Table is %s\n", bothway ? "enable" : "disable");
	click_chatter("Box in chain is %s\n", lbInTheChain ? "yes" : "no");

	//click_chatter("flowBased LB  is %s\n", sampleLB ? "enable" : "disable");
	//click_chatter("flowBased FW  is %s\n", sampleFW ? "enable" : "disable");
	//click_chatter("flowBased IDS is %s\n", sampleIDS ? "enable" : "disable");
	click_chatter("===============================================\n");
	std::string start = encTools::timeNow();
	click_chatter("===============================================\n");
	std::string end = encTools::timeNow();
	click_chatter("output one line use %lf ns.\n", encTools::differTimeInNsec(start.data(), end.data()));

	boxLogger.open(string(eleOutputPath).append(outputExtension));
	pktLogger.open(string(pktOutputPath).append(outputExtension));
	pktContainer.reserve(maxPktUsed);

	validTotalPkgCount = 0;
	boxCounter.no = 1;

	VeriTools::initIDS(&pm_engine, patterns);
	click_chatter("Load %d patterns.\n", patterns.size());

	boxTotalTime = 0;
	preTime = encTools::timeNow();
	activityTime = encTools::timeNow();

	return 0;
}

void MiddleboxIDS::push(int port, Packet * p_in)
{
	if (localMode&& validTotalPkgCount >= maxPktUsed - 10)
	{
		for (auto it = pktContainer.begin(); it != pktContainer.end(); ++it)
		{
			pktLogger << *it;
		}
		click_chatter("===============================================\n");
		click_chatter("Write file end.\n");
		click_chatter("===============================================\n");
		validTotalPkgCount = 0;
	}

	std::string beginTime = encTools::timeNow();

	if (!VeriTools::isTestPacket(p_in))
	{
		if (justSend)
		{
			WritablePacket *p = p_in->uniqueify();
			//########################  different in each box
			VeriTools::reDirectionPacket(p, boxIDS_src_ip, boxIDS_src_mac, boxIDS_dst_ip, boxIDS_dst_mac);
			ready_packet.push_back(p);
			boxCounter.pktCount += 1;
			boxCounter.pktSize += p_in->length();
			boxCounter.pktPageloadSize += PktReader(p_in).getDataLength();
			VeriTools::checkElementCounter(boxCounter, preTime, eleContainer);
			++validTotalPkgCount;
			if (validTotalPkgCount == maxPktUsed)
			{
				for (auto it = eleContainer.begin(); it != eleContainer.end(); ++it)
				{
					boxLogger << *it;
				}
				click_chatter("wait to write :%d\n", validTotalPkgCount);
			}
		}
		else
		{
			static bool wroteFile = false;
			static string waitTime = "";
			if (!wroteFile && (validTotalPkgCount == maxPktUsed || encTools::differTimeInNsec(activityTime.data(), encTools::timeNow().data()) > elementCounterBaseGap * 10.0))
			{
				if (waitTime.size() > 0)
				{
					if (encTools::differTimeInNsec(waitTime.data(), encTools::timeNow().data()) > elementCounterBaseGap*2)
					{
						for (auto it = eleContainer.begin(); it != eleContainer.end(); ++it)
						{
							boxLogger << *it;
						}
						for (auto it = pktContainer.begin(); it != pktContainer.end(); ++it)
						{
							pktLogger << *it;
						}
						wroteFile = true;
						click_chatter("===============================================\n");
						click_chatter("Write file end.\n");
						click_chatter("===============================================\n");
					}
				}
				else
				{
					click_chatter("===============================================\n");
					click_chatter("wait to write :%d\n", validTotalPkgCount);
					click_chatter("box avg use %lf ns.\n", boxTotalTime / maxPktUsed);
					click_chatter("===============================================\n");
					waitTime = encTools::timeNow();
				}
			}

			p_in->kill();
		}
		return;
	}

	// 1. get pkt batch
	PktReader reader(p_in);
	VeriHeader * pveri = (VeriHeader *)reader.getIpOption();
	boxBatch& batch = batches[pveri->batchID];
	if (batch.packetCount == 0)
	{
		//########################  different in each box
		VeriTools::initBoxBatch(batch, pveri->batchID, flowBasedVerify, IDS);
		batch.readyToSendRoot = false;
	}

	WritablePacket *p = 0;

	// 2. check if special pkt
	if (pveri->flowID == trickFlowID)
	{
		batch.batchPktSize = pveri->cNum;
		if (!idsInTheChain)
		batch.readyToSendRoot = true;
		if (verbose)
		click_chatter("Recv batch size pkt, batchID:%d, size:%d\n", pveri->batchID, pveri->cNum);

		WritablePacket *p = p_in->uniqueify();
		VeriTools::reDirectionPacket(p, boxIDS_src_ip, boxIDS_src_mac, boxIDS_dst_ip, boxIDS_dst_mac);
		ready_packet.push_back(p);
	}
	else if (pveri->flowID == merkletreeRootFlowID)
	{
		if (idsInTheChain)
		batch.readyToSendRoot = true;
		memcpy(batch.rootPacket, p_in->data(), p_in->length());
		if(verbose)
		click_chatter("Recv merkle_tree root pkt, tree root count is %d.\n", ((VeriHeader*)(reader.getIpOption()))->cNum);
		p_in->kill();
	}
	else
	{
		pktCounter boxPktCounter;
		VeriTools::setPktCounter(boxPktCounter, p_in);

		// 3. add pkt to batch
		batch.packetCount++;
		pktFlow& flow = batch.flows[pveri->flowID];
		if (flow.packetCount == 0)
		{
			VeriTools::initFlow(flow, batch.batchID, pveri->flowID);
		}
		flow.packetCount++;


		// 4. do box function
		//########################  different in each 
		p = p_in->uniqueify();
		if (!p)
		{
			click_chatter("uniqueify error\n");
			return;
		}
		VeriTools::patternMatching(pm_engine, p->data(), p->length());

		VeriTools::reDirectionPacket(p, boxIDS_src_ip, boxIDS_src_mac, boxIDS_dst_ip, boxIDS_dst_mac);
		ready_packet.push_back(p);
		reader.attach(p);
		//VeriTools::showPacket(p);

		// 5. update veriInfo
		if (veriSwitch)
		{
			veriInfo& veri = batch.veriRes[flow.flowID];
			VeriTools::updateFlowVeri(veri, VeriTools::fflowIDS(p), p);
		}

		activityTime = encTools::timeNow();
		if (!startTime.size())
		{
			startTime = activityTime;
		}
		boxPktCounter.timestamp = encTools::differTimeInNsec(startTime.data(), activityTime.data());
		startTime = activityTime;
		boxPktCounter.processTime = encTools::differTimeInNsec(beginTime.data(), activityTime.data());
		pktContainer.push_back(VeriTools::formatPktCounter(boxPktCounter));

		boxCounter.pktCount += 1;
		boxCounter.pktSize += p->length();
		boxCounter.pktPageloadSize += reader.getDataLength();
		VeriTools::checkElementCounter(boxCounter, preTime, eleContainer);
		validTotalPkgCount++;

		if (verbose)
		{
			click_chatter("process batch:%d flow:%d cum:%d pkt use time :%lf ns .\n", pveri->batchID, pveri->flowID, pveri->cNum, boxPktCounter.processTime);
		}
	}


	// 6.handle full batch
	if (veriSwitch)
		if (batch.readyToSendRoot)
			if (batch.batchPktSize == batch.packetCount)
			{
				if (batch.typeV == pktBasedVerify)
				{
					if ((batch.packetCount & batch.packetCount - 1) != 0)
					{
						click_chatter("batch packetCount error %d\n", batch.packetCount);
						return;
					}
					//click_chatter("pkt based tree\n");
					buildTreeAndSendRootPkt(batch);
				}
				else
				{
					if ((batch.veriRes.size() & batch.veriRes.size() - 1) != 0)
					{
						click_chatter("batch flowCount error %d\n", batch.flows.size());
						return;
					}
					buildTreeAndSendRootPkt(batch);
				}
			}
			else
			{
				if (verbose)
				{
					click_chatter("batch need size %d, batch real size %d \n", batch.batchPktSize, batch.packetCount);
				}
			}
	boxTotalTime += encTools::differTimeInNsec(beginTime.data(), encTools::timeNow().data());
}

Packet* MiddleboxIDS::pull(int port) {
	Packet* p = 0;
	if (!ready_packet.empty())
	{
		p = ready_packet.front();
		ready_packet.pop_front();
	}

	return p;
}

void MiddleboxIDS::buildTreeAndSendRootPkt(boxBatch & batch)
{
	VeriTools::buildVeriTree(batch);

	WritablePacket* pktRoot = VeriTools::makeUDPPacket();
	PktReader reader(pktRoot);
	VeriHeader * pveri = (VeriHeader *)reader.getIpOption();

	VeriHeader* oldVeriHeader = (VeriHeader*)(batch.rootPacket + ether_len + ip_default_len);

	pveri->flowID = merkletreeRootFlowID;
	pveri->batchID = batch.batchID;
	pveri->cNum += oldVeriHeader->cNum + 1;

	if (pveri->cNum != 1)
	{
		if(verbose)
		click_chatter("find box chain, this box is No.%d box.\n", pveri->cNum);
		memcpy((uint8_t*)(pveri + 1) + udp_default_len, (uint8_t*)(oldVeriHeader + 1) + udp_default_len,
			encTools::SHA256_len*(pveri->cNum - 1));
	}
	memcpy((char*)(pveri + 1) + encTools::SHA256_len*(pveri->cNum - 1) + udp_default_len,
		batch.tree.getRoot().c_str(), encTools::SHA256_len);

	//########################  different in each box
	VeriTools::reDirectionPacket(pktRoot, boxIDS_src_ip, boxIDS_src_mac, boxIDS_dst_ip, boxIDS_dst_mac);
	if (verbose)
	click_chatter("batch %d root packet generated and flow count is %d, veri count is %d \n", batch.batchID, batch.flows.size(), batch.veriRes.size());

	//VeriTools::showPacket(pktRoot);
	ready_packet.push_back(pktRoot);
}


CLICK_ENDDECLS
EXPORT_ELEMENT(MiddleboxIDS)
ELEMENT_MT_SAFE(MiddleboxIDS)
ELEMENT_LIBS(-lverimb -lcryptopp)
