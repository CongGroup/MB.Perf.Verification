require("click_verimb")

box :: MiddleboxLB();



FromDump(./200xb.pcap)
	-> [0]box
	-> ToDump(./tmp.pcap);


//FromDevice(ens5, SNIFFER true)
//	-> [0]box
//	-> ToDevice(ens5);
//
