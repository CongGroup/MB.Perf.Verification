require("click_verimb")

define($PKT_SOURCE ./200x.pcap);
define($BATCH_SIZE 1024);
define($EXP_SIZE 102600);
define($VERIFY 0);
define($DISABLE_NETWORK 1);
define($BASELINE 0);
define($QUEYR_TABLE 0);
define($IN_CHAIN 0);

box :: MiddleboxLB(
BATCH_SIZE $BATCH_SIZE, EXP_SIZE $EXP_SIZE,
VERIFY $VERIFY, DISABLE_NETWORK $DISABLE_NETWORK, BASELINE $BASELINE,
QUEYR_TABLE $QUEYR_TABLE, IN_CHAIN $IN_CHAIN);

FromDump($PKT_SOURCE)
	-> [0]box
	-> ToDump(./m59.pcap);

//FromDump(./200xb.pcap)
//	-> [0]box
//	-> ToDump(./tmp.pcap);


//FromDevice(ens5, SNIFFER true)
//	-> [0]box
//	-> ToDevice(ens5);

