require("click_verimb")


define($PKT_SOURCE ./m57.pcap);
define($BATCH_SIZE 1024);
define($EXP_SIZE 400000);
define($VERIFY 1);
define($DISABLE_NETWORK 0);
define($BASELINE 1);
define($QUEYR_TABLE 0);
define($IN_CHAIN 0);

gw :: GatewaySender(
BATCH_SIZE $BATCH_SIZE, EXP_SIZE $EXP_SIZE,
VERIFY $VERIFY, DISABLE_NETWORK $DISABLE_NETWORK, BASELINE $BASELINE,
QUEYR_TABLE $QUEYR_TABLE, IN_CHAIN $IN_CHAIN);

//FromDump(./m57.pcap)
//	-> [0]gw
//	-> ToDump(./m58.pcap);


//FromDump($PKT_SOURCE)
//	-> BandwidthShaper(2000000)
//	-> Unqueue()
//	-> [0]gw
//	-> ToDevice(ens5);

FromDump($PKT_SOURCE)
	-> Unqueue()
	-> [0]gw
	-> ToDevice(ens5);

FromDevice(ens5, SNIFFER true)
	-> [1]gw;


