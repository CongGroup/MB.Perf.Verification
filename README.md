# MB.Perf.Verification

 * Introduction
 * Publication
 * Requirements
 * Installation
 * Configuration
 * Compiling
 * Usage
 * Maintainers

# INTRODUCTION

To be continued.

# PUBLICATION

To be continued.

# REQUIREMENTS

Recommended Environment: Ubuntu 16.04 LTS with gcc version 4.8.4.

This software requires the following libraries:

 * [Crypto++](https://www.cryptopp.com/)
 * [Click Modular Router](https://github.com/kohler/click)

# INSTALLATION

* Environment setup:

```shell
 * sudo apt-get update
 * sudo apt-get install -y lrzsz gcc g++ libssl-dev libgmp-dev subversion make cmake libboost-dev libboost-test-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev libevent-dev automake libtool flex bison pkg-config ssh openssh-server rsync python-software-properties libglib2.0-dev git libmsgpack-dev libboost-thread-dev libboost-date-time-dev libhiredis-dev build-essential libboost-regex-dev gdb
```

* Crypto++ installation:

You can find the [version 5.6.5](https://www.cryptopp.com/cryptopp565.zip) on crypto++ website.

```shell
wget https://github.com/weidai11/cryptopp/archive/CRYPTOPP_5_6_5.tar.gz
tar -zxf CRYPTOPP_5_6_5.tar.gz
cd cryptopp-CRYPTOPP_5_6_5
make libcryptopp.a libcryptopp.so 
sudo make install PREFIX=/usr/local
```

* Click installation:


```shell
git clone https://github.com/kohler/click.git
cd click
./configure --prefix=/usr/local
sudo make install
```


# CONFIGURATION

 Configure the environment

	Add the libraries paths to $LD_LIBRARY_PATH.

	```shell
	* export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
	```

	network configure.
	```shell
	sudo ethtool -K ens5 gso off gro off
	sudo ifconfig ens5 mtu 1500
	```

# COMPILING

Compile MB.Perf.Verification:

```shell
 * git clone https://github.com/CongGroup/MB.Perf.Verification.git
 * cd MB.Perf.Verification
 * sudo make
```

# USAGE

1. Configure ip address
open src/element/element_config.h and modify the ip and mac.

2. Configure click configure
open VeriNFsMB/click_config/*.click file and modify the network structure.
```
$PKT_SOURCE is the source packet file path
$BATCH_SIZE is batch size.
$EXP_SIZE is the packets count in the exp.
$VERIFY is the switch of verify function.
$IN_CHAIN if the middlebox is not the head of middlebox chain, this switch need to enable.
```

3. Start middlebox first, then start gateway
```
user@middlebox: sudo click box.click

user@gateway1: sudo click gateway1.click
```
 

# MAINTAINER

  - Xiaoli Zhang, City University of Hong Kong, xiaoli.z@outlook.com
  - Mengyu Yao, City University of Hong Kong, mengycs@gmail.com
