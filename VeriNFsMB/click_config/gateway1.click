require("click_verimb")

gw :: GatewaySender();

FromDump(./m57.pcap)
	-> [0]gw
	-> ToDump(./m58.pcap);

//FromDump(./m57.pcap)
//	-> BandwidthShaper(2000000)
//	-> Unqueue()
//	-> [0]gw
//	-> ToDevice(ens5);
//
//FromDevice(ens5, SNIFFER true)
//	-> [1]gw;
//

