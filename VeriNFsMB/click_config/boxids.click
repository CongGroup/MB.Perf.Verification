require("click_verimb")

box :: MiddleboxIDS();

FromDump(./m58.pcap)
	-> [0]box
	-> ToDump(./m59.pcap);


//
//FromDevice(ens5, SNIFFER true)
//	-> [0]box
//	-> ToDevice(ens5);
//