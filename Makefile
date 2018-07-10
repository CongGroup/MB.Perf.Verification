all:
	cd ./VeriNFsMB/src/libverimb/; rm -f *.o; rm -f *.so; sudo make; cd ../../../
	cd ./VeriNFsMB/src/element/; make clean; autoconf; ./configure; sudo make install; cd ../../../
