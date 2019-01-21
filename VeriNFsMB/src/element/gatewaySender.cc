/*
* print.{cc,hh} -- element prints packet contents to system log
* John Jannotti, Eddie Kohler
*
* Copyright (c) 1999-2000 Massachusetts Institute of Technology
* Copyright (c) 2008 Regents of the University of California
*
* Permission is hereby granted, free of charge, to any person obtaining a
* copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, subject to the conditions
* listed in the Click LICENSE file. These conditions include: you must
* preserve this copyright notice, and you cannot mention the copyright
* holders in advertising related to the Software without their permission.
* The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
* notice is a summary of the Click LICENSE file; the license in that file is
* legally binding.
*/

#include <click/config.h>
#include <click/args.hh>
#include <click/error.hh>
#include <click/integers.hh>
#include <clicknet/ip.h>

#include "gatewaySender.hh"

#include <time.h>

#include <sys/socket.h>

using std::string;


CLICK_DECLS

GatewaySender::GatewaySender()
{
}

GatewaySender::~GatewaySender()
{
}


static int veriSwitch = true;
static bool justSend = false;
static bool localMode = false;
static bool bothway = false;
static int  batch_element_size = 1024;
static int  maxPktUsed = 1024 * 10 * 10 + 200;
static bool lbInTheChain = false;
static bool fwInTheChain = false;
static bool idsInTheChain = false;

int
GatewaySender::configure(Vector<String> &conf, ErrorHandler* errh)
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
		.complete() < 0 )
	{
		return -1;
	}

	if (inChain)
	{
		lbInTheChain  = true;
		fwInTheChain  = true;
		idsInTheChain = true;
	}	
	else
	{
		lbInTheChain  = false;
		fwInTheChain  = false;
		idsInTheChain = false;
	}

	return 0;
}

int GatewaySender::initialize(ErrorHandler *errh)
{
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

	// current batch and his flows
	gatewayBatch currentBatch;
	initBatch(currentBatch);
	batches.push_back(currentBatch);

	gateway1Logger.open(string(eleOutputPath).append("1").append(outputExtension));
	gateway2Logger.open(string(eleOutputPath).append("2").append(outputExtension));
	pkt1Logger.open(string(pktOutputPath).append("1").append(outputExtension));
	pkt2Logger.open(string(pktOutputPath).append("2").append(outputExtension));

	gateway1Counter.no = 1;
	gateway2Counter.no = 1;

	pkt1Container.reserve(maxPktUsed);
	pkt2Container.reserve(maxPktUsed);

	preTime1 = encTools::timeNow();
	preTime2 = encTools::timeNow();
	activityTime = encTools::timeNow();


	totalPktCount = 0;
	totalGateway1Time = 0;
	totalGateway2Time = 0;

	pktCache = new unsigned char*[maxPktUsed];
	for (int i = 0; i < maxPktUsed; i++)
	{
		pktCache[i] = new unsigned char[ether_max_size];
	}

	bool genData = false;
	if (genData)
	{

	}

	return 0;
}



void GatewaySender::push(int port, Packet * p_in)
{
	std::string beginTime = encTools::timeNow();

	//if (++totalPktCount > maxPktUsed)
	//{
	//	p_in->kill();
	//	return;
	//}
	//if (port == 0)
	//{
	//	ready_packet.push_back(p_in);
	//	click_chatter("send org pkt\n");
	//	WritablePacket * pkt_our = VeriTools::makeUDPPacket();
	//	VeriTools::reDirectionPacket(pkt_our, gateway1_src_ip, gateway1_src_mac, gateway1_dst_ip, gateway1_dst_mac);
	//	ready_packet.push_back(pkt_our);
	//	click_chatter("send our pkt\n");
	//}
	//return;

	if (port == 0)
	{
		//end flag
		if (++totalPktCount > maxPktUsed)
		{
			p_in->kill();
			return;
		}

		if (justSend)
		{
			WritablePacket *p = p_in->uniqueify();
			VeriTools::reDirectionPacket(p, gateway1_src_ip, gateway1_src_mac, gateway1_dst_ip, gateway1_dst_mac);
			ready_packet.push_back(p);
			gateway1Counter.pktCount += 1;
			gateway1Counter.pktSize += p_in->length();
			gateway1Counter.pktPageloadSize += PktReader(p_in).getDataLength();
			VeriTools::checkElementCounter(gateway1Counter, preTime1, ele1Container);
			return;
		}

		// 0. sample pkt
		if (veriSwitch)
		if (!bothway)
		{
			if (!VeriTools::isSample(p_in))
			{
				// if not sample, do nothing.
				return;
			}
		}
		else
		{
			// if enable bothway, look up table, and then sample this pkt;
			string fiveTuple = VeriTools::fiveTuple(p_in);
			auto iter = five_tuple_loolup_table.find(fiveTuple);
			if (iter != five_tuple_loolup_table.end())
			{
				iter->second += 1;
			}
			else
			{
				if (!VeriTools::isSample(p_in))
				{
					// if not sample, do nothing.
					return;
				}
				five_tuple_loolup_table[fiveTuple] = 0;
			}
		}

		//get batch
		gatewayBatch& currentBatch = *(batches.end() - 1);

		// 1. use org 5-tuple to pick one flow
		pktCounter pkt1Counter;
		pktFlow& orgflow = flowFilter[(VeriTools::fiveTuple(p_in))];
		if (orgflow.packetCount == 0)
		{
			currentBatch.flowCount += 1;
			VeriTools::initFlow(orgflow, currentBatch.batchID, currentBatch.flowCount);
		}
		orgflow.packetCount++;

		// 2. add veriHeader to pkt
		WritablePacket *p = addVeriHeader(p_in);
		VeriTools::setPktCounter(pkt1Counter, p);

		// 3. save this pkt to flow and batch
		string flowKey = (VeriTools::fiveTuple(p));
		pktFlow& flow = allFlows[flowKey];
		if (flow.packetCount == 0)
		{
			VeriTools::initFlow(flow, currentBatch.batchID, currentBatch.flowCount);
		}
		flow.packetCount++;
		currentBatch.packetCount++;

		// 4. do veri or cache pkt
		if (pktCache != 0)
		{
			memcpy(pktCache[totalPktCount - 1], p->data(), p->length());
		}

		// 6. prepare to send pkt 
		VeriTools::reDirectionPacket(p, gateway1_src_ip, gateway1_src_mac, gateway1_dst_ip, gateway1_dst_mac);
		//VeriTools::showPacket(p);


		// 5. mark timestamp and send
		R1 r1;
		r1.batchID = flow.batchID;
		r1.pktID = VeriTools::getPktID(flow.flowID, flow.packetCount);
		std::string timeStr = encTools::timeNow();
		memcpy(r1.timeIn, timeStr.data(), timeStr.length());
		currentBatch.r1s.push_back(r1);
		currentBatch.r2s.push_back(R2());

		activityTime = timeStr;
		if (!startTime1.size())
		{
			startTime1 = timeStr;
		}
		pkt1Counter.timestamp = encTools::differTimeInNsec(startTime1.data(), timeStr.data());
		startTime1 = timeStr;
		pkt1Counter.processTime = encTools::differTimeInNsec(beginTime.data(), timeStr.data());
		pkt1Container.push_back(VeriTools::formatPktCounter(pkt1Counter));

		gateway1Counter.pktCount += 1;
		gateway1Counter.pktSize += p->length();
		gateway1Counter.pktPageloadSize += PktReader(p).getDataLength();
		VeriTools::checkElementCounter(gateway1Counter, preTime1, ele1Container);

		ready_packet.push_back(p);
		if (verbose)
		{
			click_chatter("process batch:%d flow:%d cum:%d pkt use time :%lf ns .\n", currentBatch.batchID, flow.flowID, flow.packetCount, pkt1Counter.processTime);
		}

		//7.handle batch end
		if (false)
		{
			if (currentBatch.packetCount == currentBatch.batchSize)
			{
				gatewayBatch nextBatch;
				initBatch(nextBatch);
				batches.push_back(nextBatch);
				flowFilter.clear();
				allFlows.clear();
			}
		}
		else
		{
			if (currentBatch.flowCount == currentBatch.batchSize)
			{
				// 7.1 notice box batch real size
				WritablePacket* batchPkt = makeSpecialPkt(p, currentBatch.packetCount);
				VeriTools::reDirectionPacket(batchPkt, gateway1_src_ip, gateway1_src_mac, gateway1_dst_ip, gateway1_dst_mac);
				ready_packet.push_back(batchPkt);

				// 7.3 save batch
				gatewayBatch nextBatch;
				initBatch(nextBatch);
				batches.push_back(nextBatch);
				flowFilter.clear();
				allFlows.clear();
			}
		}

		totalGateway1Time += encTools::differTimeInNsec(beginTime.data(), encTools::timeNow().data());
	}
	else if (port == 1)
	{
		if (!VeriTools::isTestPacket(p_in))
		{
			if (justSend)
			{
				gateway2Counter.pktCount += 1;
				gateway2Counter.pktSize += p_in->length();
				gateway2Counter.pktPageloadSize += PktReader(p_in).getDataLength();
				VeriTools::checkElementCounter(gateway2Counter, preTime2, ele2Container);
				validTotalPkgCount++;
				if (validTotalPkgCount == maxPktUsed)
				{
					for (auto it = ele1Container.begin(); it != ele1Container.end(); ++it)
					{
						gateway1Logger << *it;
					}
					for (auto it = ele2Container.begin(); it != ele2Container.end(); ++it)
					{
						gateway2Logger << *it;
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
						if (encTools::differTimeInNsec(waitTime.data(), encTools::timeNow().data()) > elementCounterBaseGap * 2)
						{
							for (auto it = ele1Container.begin(); it != ele1Container.end(); ++it)
							{
								gateway1Logger << *it;
							}
							for (auto it = ele2Container.begin(); it != ele2Container.end(); ++it)
							{
								gateway2Logger << *it;
							}
							for (auto it = pkt1Container.begin(); it != pkt1Container.end(); ++it)
							{
								pkt1Logger << *it;
							}
							for (auto it = pkt2Container.begin(); it != pkt2Container.end(); ++it)
							{
								pkt2Logger << *it;
							}
							wroteFile = true;
							click_chatter("===============================================\n");
							click_chatter("Write file end.\n");
							click_chatter("Gateway1 avg use %lf ns, Gateway2 avg use %lf ns.\n", totalGateway1Time / maxPktUsed, totalGateway2Time / maxPktUsed);
							click_chatter("===============================================\n");
						}
					}
					else
					{
						click_chatter("===============================================\n");
						click_chatter("wait to write :%d\n", validTotalPkgCount);
						click_chatter("===============================================\n");
						waitTime = encTools::timeNow();
						gateway1Counter.useTime = elementCounterBaseGap;
						gateway2Counter.useTime = elementCounterBaseGap;
						VeriTools::checkElementCounter(gateway1Counter, preTime1, ele1Container);
						VeriTools::checkElementCounter(gateway2Counter, preTime2, ele2Container);
					}
				}
			}
			p_in->kill();
			return;
		}


		PktReader reader(p_in);
		VeriHeader* pveri = (VeriHeader*)reader.getIpOption();
		pktCounter pkt2Counter;
		VeriTools::setPktCounter(pkt2Counter, p_in);

		if (pveri->flowID == trickFlowID)
		{
			p_in->kill();
			return;
		}
		else if (pveri->flowID == merkletreeRootFlowID)
		{
			for (int i = 0; i < batches.size(); i++)
			{
				if (batches[i].batchID == pveri->batchID)
				{
					gatewayBatch&batch = batches[i];

					char* pRoot = (char*)reader.getData() + udp_default_len;

					if (veriSwitch>0)
					{
						batch.rootFlowLB.assign(pRoot, encTools::SHA256_len);
						pRoot += encTools::SHA256_len;
					}
					if (veriSwitch>1)
					{
						batch.rootFlowFW.assign(pRoot, encTools::SHA256_len);
						pRoot += encTools::SHA256_len;
					}
					if (veriSwitch>2)
					{
						batch.rootFlowIDS.assign(pRoot, encTools::SHA256_len);
						pRoot += encTools::SHA256_len;
					}
					batch.batchResultPktCount += 1;
					if (verbose)
						click_chatter("batch %d tree root received.\n", batch.batchID);
					//checkBatchTime(batch);
					break;
				}
			}
			p_in->kill();
			return;
		}

		// sample
		//VeriTools::isSample(p_in);

		bool __found = false;
		for (int i = 0; i < batches.size(); i++)
		{
			if (batches[i].batchID == pveri->batchID)
			{
				gatewayBatch&batch = batches[i];
				uint64_t pktID = VeriTools::getPktID(pveri->flowID, pveri->cNum);
				for (int j = 0; j < batch.r1s.size(); j++)
				{
					if (batch.r1s[j].pktID == pktID)
					{
						__found = true;
						batch.batchResultPktCount += 1;

						R2& r2 = batch.r2s[j];
						r2.batchID = batch.batchID;
						r2.pktID = pktID;
						std::string timeStr = encTools::timeNow();
						memcpy(r2.timeOut, timeStr.data(), timeStr.length());

						double diffTime = encTools::differTimeInNsec(batch.r1s[j].timeIn, batch.r2s[j].timeOut);
						//batch.counter.totalTime += diffTime;

						activityTime = timeStr;
						if (!startTime2.size())
						{
							startTime2 = timeStr;
						}
						pkt2Counter.timestamp = encTools::differTimeInNsec(startTime2.data(), timeStr.data());
						startTime2 = timeStr;
						pkt2Counter.processTime = encTools::differTimeInNsec(beginTime.data(), timeStr.data());
						pkt2Counter.delay = diffTime;
						pkt2Container.push_back(VeriTools::formatPktCounter(pkt2Counter));

						validTotalPkgCount++;
						if (verbose)
						{
							click_chatter("pktR2: batchid:%d flowID:%d pktID:%d useTime:%lf ns.\n",
								pveri->batchID, pveri->flowID, pveri->cNum, diffTime);
						}

						break;
					}
				}
				//checkBatchTime(batch);
				if (__found)
					break;
			}
		}

		gateway2Counter.pktCount += 1;
		gateway2Counter.pktSize += p_in->length();
		gateway2Counter.pktPageloadSize += PktReader(p_in).getDataLength();
		VeriTools::checkElementCounter(gateway2Counter, preTime2, ele2Container);

		if (!__found)
		{
			click_chatter("##### missed return pkg \n");
			validTotalPkgCount++;
			VeriTools::showPacket(p_in);
		}
		totalGateway2Time += encTools::differTimeInNsec(beginTime.data(), encTools::timeNow().data());
	}

}

Packet* GatewaySender::pull(int port) {
	Packet* p = 0;
	if (!ready_packet.empty())
	{
		p = ready_packet.front();
		ready_packet.pop_front();
		//VeriTools::showPacket(p);
		//update R1 of p
		if (VeriTools::isTestPacket(p))
		{
			PktReader reader(p);
			VeriHeader* pveri = (VeriHeader*)reader.getIpOption();

			bool __found = false;
			for (int i = 0; i < batches.size(); i++)
			{
				if (batches[i].batchID == pveri->batchID)
				{
					gatewayBatch&batch = batches[i];
					uint64_t pktID = VeriTools::getPktID(pveri->flowID, pveri->cNum);
					for (int j = 0; j < batch.r1s.size(); j++)
					{
						if (batch.r1s[j].pktID == pktID)
						{
							__found = true;
							std::string timeStr = encTools::timeNow();
							memcpy(batch.r1s[j].timeIn, timeStr.data(), timeStr.length());
							break;
						}
					}
					if (__found)
						break;
				}
			}
		}
	}

	return p;
}

WritablePacket * GatewaySender::addVeriHeader(Packet * pkt_in)
{
	gatewayBatch& currentBatch = *(batches.end() - 1);

	PktReader reader(pkt_in);
	if (reader.getIPHeaderLength() != ip_default_len)
	{
		click_chatter("Error IP Header Length: %d\n", reader.getIPHeaderLength());
		pkt_in->kill();
		return 0;
	}

	VeriHeader veriHeader;
	veriHeader.batchID = currentBatch.batchID;

	pktFlow& orgflow = flowFilter[(VeriTools::fiveTuple(pkt_in))];
	veriHeader.flowID = orgflow.flowID;
	veriHeader.cNum = orgflow.packetCount;

	WritablePacket *p = pkt_in->push(sizeof(VeriHeader));
	reader.attach(p);

	//copy therer header
	memmove(p->data(), p->data() + sizeof(VeriHeader), ether_len + ip_default_len);

	click_ip* c_ip = (click_ip*)(p->data() + ether_len);
	c_ip->ip_hl += sizeof(VeriHeader) / 4;
	c_ip->ip_len = htons(reader.getIPTotalLength() + sizeof(VeriHeader));

	memcpy(p->data() + ether_len + ip_default_len, &veriHeader, sizeof(veriHeader));
	return p;
}

WritablePacket * GatewaySender::makeSpecialPkt(Packet * pkt_ref, int batchCount)
{
	WritablePacket* p = Packet::make(pkt_ref->data(), pkt_ref->length());
	PktReader r(p);
	VeriHeader* pv = (VeriHeader*)(r.getIpOption());
	pv->flowID = trickFlowID;
	pv->cNum = batchCount;
	return p;
}
//
//double GatewaySender::checkBatchTime(gatewayBatch & batch)
//{
//	int expectSize = ((int)samplePktLB + (int)sampleLB + (int)sampleFW + (int)sampleIDS) + batch.packetCount;
//	double totalTime = 0;
//	if (batch.batchResultPktCount == expectSize)
//	{
//		for (int i = 0; i < batch.r1s.size()-1; i++)
//		{
//			if (batch.r2s[i].pktID != 0)
//			{
//				totalTime += encTools::differTimeInNsec(batch.r1s[i].timeIn, batch.r2s[i].timeOut);
//			}
//		}
//		totalTime /= (batch.r1s.size()-1);
//	}
//
//	if (totalTime > 0)
//	{
//		click_chatter("pktR2: batchid:%d avg useTime:%lf ns.\n", batch.batchID, totalTime);
//		batchCounter& counter = batch.counter;
//		counter.batchID = batch.batchID;
//		counter.flowCount = batch.flowCount;
//		counter.pktCount = batch.packetCount;
//		counter.avgPkgTime = totalTime;
//		click_chatter("%s.\n", VeriTools::formatBatchCounter(counter).c_str());
//	}
//	return totalTime;
//}
//


void GatewaySender::initBatch(gatewayBatch & batch)
{
	batch.batchID = batches.size() + 1;
	batch.batchSize = batch_element_size;
	batch.flowCount = 0;
	batch.packetCount = 0;
	batch.batchResultPktCount = 0;
}


CLICK_ENDDECLS
EXPORT_ELEMENT(GatewaySender)
ELEMENT_MT_SAFE(GatewaySender)
ELEMENT_LIBS(-lverimb -lcryptopp)
