require("click_verimb")

define($BATCH_SIZE 1024);
define($EXP_SIZE 1000000);
define($VERIFY 1);
define($DISABLE_NETWORK 0);
define($BASELINE 1);
define($QUEYR_TABLE 0);
define($IN_CHAIN 1);

box :: MiddleboxLB(
BATCH_SIZE $BATCH_SIZE, EXP_SIZE $EXP_SIZE,
VERIFY $VERIFY, DISABLE_NETWORK $DISABLE_NETWORK, BASELINE $BASELINE,
QUEYR_TABLE $QUEYR_TABLE, IN_CHAIN $IN_CHAIN);

//FromDump(./200xb.pcap)
//	-> [0]box
//	-> ToDump(./tmp.pcap);
//

FromDevice(ens5, SNIFFER true)
	-> [0]box
	-> ToDevice(ens5);

