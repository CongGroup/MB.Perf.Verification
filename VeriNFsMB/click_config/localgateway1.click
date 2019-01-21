require("click_verimb")


define($BATCH_SIZE 1024);
define($EXP_SIZE 102600);
define($VERIFY 1);
define($DISABLE_NETWORK true);
define($BASELINE false);
define($QUEYR_TABLE false);
define($IN_CHAIN false);

gw :: GatewaySender(
BATCH_SIZE $BATCH_SIZE, EXP_SIZE $EXP_SIZE,
VERIFY $VERIFY, DISABLE_NETWORK $DISABLE_NETWORK, BASELINE $BASELINE,
QUEYR_TABLE $QUEYR_TABLE, IN_CHAIN $IN_CHAIN);

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


