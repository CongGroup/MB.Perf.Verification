#pragma once

const bool isAzure = false;
const char *const  azureDstMac = "12:34:56:78:9a:bc";

//wifi
//#define ip_verm_3 "192.168.1.15"
//#define mac_verm_3 "f0:d5:bf:38:97:e4"

//local lan
//#define ip_verm_1 "192.168.1.5"
//#define mac_verm_1 "18:db:f2:27:91:f8"
//
//#define ip_verm_2 "192.168.1.2"
//#define mac_verm_2 "18:db:f2:27:92:95"


//Azure eth0
//#define ip_verm_1 "10.1.2.4"
//#define mac_verm_1 "00:0d:3a:a3:35:24"
//
//#define ip_verm_2 "10.1.2.5"
//#define mac_verm_2 "00:0d:3a:a3:37:99"


//machine info
//AWS ens5
#define ip_verm_1 "172.31.42.246"
#define mac_verm_1 "0a:24:5a:b4:0c:d6"

#define ip_verm_2 "172.31.34.153"
#define mac_verm_2 "0a:b5:da:02:8c:f2"

#define ip_verm_3 "172.31.33.60"
#define mac_verm_3 "0a:08:5f:d7:76:e0"

#define ip_verm_4 "172.31.42.222"
#define mac_verm_4 "0a:68:e3:60:89:56"

#define ip_verm_5 "192.168.1.15"
#define mac_verm_5 "18:db:f2:27:91:f8"

// exp config
#define gateway1_src_ip   ip_verm_1
#define gateway1_src_mac mac_verm_1
#define gateway1_dst_ip   ip_verm_2
#define gateway1_dst_mac mac_verm_2

#define boxFW_src_ip      ip_verm_2
#define boxFW_src_mac    mac_verm_2
#define boxFW_dst_ip      ip_verm_1
#define boxFW_dst_mac    mac_verm_1

#define boxIDS_src_ip     ip_verm_2
#define boxIDS_src_mac   mac_verm_2
#define boxIDS_dst_ip     ip_verm_1
#define boxIDS_dst_mac   mac_verm_1

#define boxLB_src_ip      ip_verm_2
#define boxLB_src_mac    mac_verm_2
#define boxLB_dst_ip      ip_verm_1
#define boxLB_dst_mac    mac_verm_1


#define gateway2_src_ip   ip_verm_2
#define gateway2_src_mac mac_verm_2
#define gateway2_dst_ip   ip_verm_1
#define gateway2_dst_mac mac_verm_1

// send pkt and disable middlebox function
//const bool justSend				= false;
//// test middlebox function without network
//const bool localMode			= true;
//// enable/disable verify
//const bool veriSwitch			= false;
//
//const bool bothway = false;
//
//const int  batch_element_size	= 1024;
//const int  maxPktUsed			= 1024 *10 *10 + 200;

const int  ether_max_size		= 1514;

const int ether_len				= 14;
const int ip_default_len		= 20;
const int tcp_default_len		= 20;
const int udp_default_len		= 8;

//const bool sampleLB				= false;
//const bool sampleFW				= false;
//const bool sampleIDS			    = false;

const unsigned short srcPort	= 12345;
const unsigned short dstPost	= 54321;

// because pkt is unorder, we use this flowID to send a special packet
// to notice middle box the batch actully pkt count.
const unsigned int trickFlowID = 0x2333;

const unsigned int merkletreeRootFlowID = trickFlowID + 1;
const unsigned int fwDropPktFlowID		= trickFlowID + 2;

const char* const firewallFilePath = "./emerging-IPF-ALL.rules";
const char * const patternFilePath = "./snort.pat";

const bool idsEngineIsAC = true;

const char* const eleOutputPath		= "eleLog";
const char* const pktOutputPath		= "pktLog";
const char* const outputExtension	= ".csv";
const bool verbose = false;

// the random number to combine flow`s pkts veri.
const int randomSeed = trickFlowID;

// if one box is in the chain, it need to receive per middlebox root pkt, then send it root
// otherwise, it send the root when it receive batch size pkt.
//const bool lbInTheChain = true;
//const bool fwInTheChain = false;
//const bool idsInTheChain = true;

// output counter per 1s
const int elementCounterBaseGap = 1000000000;

