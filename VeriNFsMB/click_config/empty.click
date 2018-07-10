require("click_verimb")

//gw1 :: GatewaySender();
//gw2 :: GatewayReceiver();
//box1 :: MiddleboxLB();
//box2 :: MiddleboxFW();
//box3 :: MiddleboxIDS();
//
//FromDump(./200.pcap) -> IPReassembler() -> ToDump(./201.pcap);
//
//FromDump(./m57.pcap)
//	-> [0]gw
//	-> ToDump(./m57xb.pcap);
//
//



//wlp2s0
//FromDump(/home/conggroup/VeriNFsMB/VeriNFsMB/click_config/srcdata/m57.pcap)
//FromDump(/home/conggroup/verimb/m57.pcap)
//-> ToDump(gateway1.pcap);
//-> ToDevice(wlp2s0);

//FromDump(gateway2.pcap)
//	-> [1]gw
//	-> ToDump(gatewayRes.pcap);

//FromDump(srcdata/m57.pcap)
//	-> [0]gw
//	-> ToDump(gateway1.pcap);