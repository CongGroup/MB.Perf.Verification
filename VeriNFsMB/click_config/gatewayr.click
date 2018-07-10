require("click_verimb")

gw :: GatewaySender();

//FromDevice(eth0, SNIFFER true)
//	-> [1]gw;

FromDump(gateway2.pcap)
	-> [1]gw
	-> ToDump(gatewayRes.pcap);

FromDump(srcdata/m57.pcap)
	-> [0]gw
	-> ToDump(gateway1.pcap);
