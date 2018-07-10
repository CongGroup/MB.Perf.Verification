#include <click/config.h>
#include <click/args.hh>
#include <click/error.hh>
#include <click/integers.hh>

#include <cmath>
#include <sys/socket.h>
#include "middleboxLB.hh"
#include "veritools.hh"

CLICK_DECLS

using namespace std;

MiddleboxLB::MiddleboxLB()
{
}

int
MiddleboxLB::configure(Vector<String> &conf, ErrorHandler* errh) {
	// Parsing
	if (Args(conf, errh)
		//.read_m("BATCH_SIZE", isFirstBox)
		.complete() < 0)
	{
		return -1;
	}
	return 0;
}

int MiddleboxLB::initialize(ErrorHandler *errh)
{
	click_chatter("===============================================\n");
	click_chatter("Batch size\t:\t%d\n", batch_element_size);
	click_chatter("Baseline test is %s\n", justSend ? "enable" : "disable");
	click_chatter("Veri function is %s\n", veriSwitch ? "enable" : "disable");
	click_chatter("Veri type     is %s\n", batchBasedPkt ? "pktBased" : "flowBased");

	click_chatter("pktBased  LB  is %s\n", samplePktLB ? "enable" : "disable");
	click_chatter("flowBased LB  is %s\n", sampleLB ? "enable" : "disable");
	click_chatter("flowBased FW  is %s\n", sampleFW ? "enable" : "disable");
	click_chatter("flowBased IDS is %s\n", sampleIDS ? "enable" : "disable");
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

	preTime = encTools::timeNow();
	activityTime = encTools::timeNow();
	startTime = encTools::timeNow();
	
	boxTotalTime = 0;
	return 0;
}

void MiddleboxLB::push(int port, Packet * p_in)
{
	if (localMode&& validTotalPkgCount > maxPktUsed)
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
	//if (PktReader(p_in).getProtocol() == IPPROTO_UDP)
	//{
	//	click_chatter("recv udp pkt\n");
	//	VeriTools::showPacket(p_in);
	//	ready_packet.push_back(p_in);
	//}
	//return;
	std::string beginTime = encTools::timeNow();

	if (!VeriTools::isTestPacket(p_in))
	{
		if (justSend)
		{
			WritablePacket *p = p_in->uniqueify();
			//########################  different in each box
			VeriTools::reDirectionPacket(p, boxLB_src_ip, boxLB_src_mac, boxLB_dst_ip, boxLB_dst_mac);
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
					boxCounter.useTime = elementCounterBaseGap;
					VeriTools::checkElementCounter(boxCounter, preTime, eleContainer);
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
		VeriTools::initBoxBatch(batch, pveri->batchID, batchBasedPkt ? pktBasedVerify : flowBasedVerify, LB);
		batch.readyToSendRoot = batchBasedPkt;
	}

	WritablePacket *p = 0;

	// 2. check if special pkt
	if (pveri->flowID == trickFlowID)
	{
		batch.batchPktSize = pveri->cNum;
		//batch.readyToSendRoot = true;
		if(verbose)
		click_chatter("Recv batch size pkt, batchID:%d, size:%d\n", pveri->batchID, pveri->cNum);

		WritablePacket *p = p_in->uniqueify();
		VeriTools::reDirectionPacket(p, boxLB_src_ip, boxLB_src_mac, boxLB_dst_ip, boxLB_dst_mac);
		ready_packet.push_back(p);
	}
	else if (pveri->flowID == merkletreeRootFlowID)
	{
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
		//select a new server and write dst ip
		uint32_t ip32bit = VeriTools::processLB(p);
		memcpy((uint8_t*)p->data() + 14 + 16, &ip32bit, sizeof(ip32bit));

		VeriTools::reDirectionPacket(p, boxLB_src_ip, boxLB_src_mac, boxLB_dst_ip, boxLB_dst_mac);
		ready_packet.push_back(p);
		//VeriTools::showPacket(p);

		// 5. update veriInfo
		if (veriSwitch&& samplePktLB)
		{
			veriInfo veri;
			veri.typeV = pktBasedVerify;
			veri.typeB = LB;
			veri.pktID = VeriTools::getPktID(flow.flowID, flow.packetCount);
			veri.field = 3;
			veri.ruleID = 0;
			VeriTools::fpktLB(p, veri);

			batch.veriRes[veri.pktID] = veri;
		}
		if (veriSwitch&& sampleLB)
		{
			veriInfo& veri = batch.veriRes[flow.flowID];
			if (veri.packetCount == 0)
			{
				veri.flowID = flow.flowID;
				veri.typeV = flowBasedVerify;
				veri.typeB = LB;
				veri.field = 3;
				veri.ruleID = 0;
				veri.mateData.assign(4, '0');
			}
			veri.packetCount += 1;
			VeriTools::setPacketMate(p, veri.packetCount, veri.mateData);
		}

		activityTime = encTools::timeNow();
		boxPktCounter.timestamp = encTools::differTimeInNsec(startTime.data(), activityTime.data());
		startTime = activityTime;
		boxPktCounter.processTime = encTools::differTimeInNsec(beginTime.data(), activityTime.data());
		pktContainer.push_back(VeriTools::formatPktCounter(boxPktCounter));

		boxCounter.pktCount += 1;
		boxCounter.pktSize += p->length();
		reader.attach(p);
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

				for (auto iterRes = batch.veriRes.begin(); iterRes != batch.veriRes.end(); iterRes++)
				{
					VeriTools::fflowLB(batch.flows[(uint32_t)iterRes->first], iterRes->second);
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

Packet* MiddleboxLB::pull(int port) {
	Packet* p = 0;
	if (!ready_packet.empty())
	{
		p = ready_packet.front();
		ready_packet.pop_front();
	}

	return p;
}

void MiddleboxLB::buildTreeAndSendRootPkt(boxBatch & batch)
{
	VeriTools::buildVeriTree(batch);

	WritablePacket* pktRoot = VeriTools::makeUDPPacket();
	PktReader reader(pktRoot);
	VeriHeader * pveri = (VeriHeader *)reader.getIpOption();

	VeriHeader* oldVeriHeader = (VeriHeader*)(batch.rootPacket + ether_len + ip_default_len);
	
	pveri->flowID = merkletreeRootFlowID;
	pveri->batchID = batch.batchID;
	pveri->cNum += oldVeriHeader->cNum+1;

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
	VeriTools::reDirectionPacket(pktRoot, boxLB_src_ip, boxLB_src_mac, boxLB_dst_ip, boxLB_dst_mac);
	if (verbose)
		click_chatter("batch %d root packet generated and flow count is %d, veri count is %d \n", batch.batchID, batch.flows.size(), batch.veriRes.size());

	//VeriTools::showPacket(pktRoot);
	ready_packet.push_back(pktRoot);
}


CLICK_ENDDECLS
EXPORT_ELEMENT(MiddleboxLB)
ELEMENT_MT_SAFE(MiddleboxLB)
ELEMENT_LIBS(-lverimb -lcryptopp)
