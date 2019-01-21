#include "veri_header.h"


#include <clicknet/ether.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include "pkt_reader.h"

using std::string;

std::string encTools::SHA256(uint8_t* str, int len)
{
	uint8_t const* pbData = (uint8_t const*)str;
	unsigned int nDataLen = len;
	uint8_t abDigest[CryptoPP::SHA256::DIGESTSIZE];

	CryptoPP::SHA256().CalculateDigest(abDigest, pbData, nDataLen);

	return string((char*)abDigest);
}

std::string encTools::SHA256(const std::string & data)
{
	uint8_t const* pbData = (uint8_t*)data.data();
	unsigned int nDataLen = data.size();
	uint8_t abDigest[CryptoPP::SHA256::DIGESTSIZE];

	CryptoPP::SHA256().CalculateDigest(abDigest, pbData, nDataLen);

	return string((char*)abDigest);
}

string encTools::timeNow()
{
	timespec timeNow;
	clock_gettime(CLOCK_REALTIME, &timeNow);
	return string().append((char*)&timeNow, sizeof(timeNow));
}

double encTools::differTimeInNsec(const char * const begin, const char * const end)
{
	timespec* b = (timespec*)begin, *e = (timespec*)end;
	return (e->tv_sec - b->tv_sec) * 1000000000 + (e->tv_nsec - b->tv_nsec);
}


