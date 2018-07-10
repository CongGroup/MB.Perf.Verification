require("click_verimb")


gw :: GatewayReceiver();

FromDevice(eth0, SNIFFER true)
	-> [0]gw
	-> ToDevice(eth0);

//-> ToDevice(wlp2s0);
//FromDump(boxLB.pcap)
//	-> GatewayReceiver()
//	-> ToDump(gateway2.pcap);
