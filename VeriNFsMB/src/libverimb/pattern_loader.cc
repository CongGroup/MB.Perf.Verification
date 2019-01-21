#include "pattern_loader.h"

#include <fstream>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>

void PatternLoader::load_pattern_file(const char* file, PatternSet& ptnSet) {
    std::ifstream inFile(file);
    if (!inFile.good()) {
        printf("Cannot open file %s\n", file);
        exit(1);
    }
    else {
        std::string line;
        //int ptrn_id = 0;
        while (std::getline(inFile, line)) {
            if (!line.empty())
                ptnSet.push_back(ptrn_str_to_bytes(line));
        }
    }
}

void PatternLoader::load_firewall_file(const char * file, std::vector<fwRule>& ruleSet)
{
	std::ifstream inFile(file);
	if (!inFile.good()) 
	{
		printf("Cannot open file %s\n", file);
		exit(1);
	}
	else 
	{
		std::string line;
		//int ptrn_id = 0;
		fwRule rule;
		while (std::getline(inFile, line)) 
		{
			if (!line.empty())
			{
				if(rule_str_to_rule(line, rule))
					ruleSet.push_back(rule);
			}
		}
	}
}

char PatternLoader::cap_hex_to_byte(const std::string & hex) {
    // first half
    char byte = (hex[0] >= '0' && hex[0] <= '9') ? (hex[0] - '0') : (hex[0] - 'A' + 10); // small letters assumed
    byte *= 16;
    // second half
    byte += (hex[1] >= '0' && hex[1] <= '9') ? (hex[1] - '0') : (hex[1] - 'A' + 10);
    return byte;
}

bool PatternLoader::rule_str_to_rule(const std::string& str, fwRule& rule)
{
	static const char* const ruleHead = "block in log quick from ";
	static const char* const connectStr = "to ";
	static const char* const anyStr = "any";

	const char* cstr = str.data();
	if (str.length() < strlen(ruleHead) || memcmp(ruleHead, cstr, strlen(ruleHead)) != 0)
	{
		return false;
	}
	cstr += strlen(ruleHead);

	char* dstr = (char*)cstr;
	while (*(++dstr) != ' '&& *dstr != 0);
	*dstr = 0;
	const char* srcip = cstr;

	cstr = dstr+1;
	if (memcmp(cstr, connectStr, strlen(connectStr)) != 0)
	{
		return false;
	}
	cstr += strlen(connectStr);
	dstr = (char*)cstr;
	while (*(++dstr) != '\n'&& *dstr != ' '&& *dstr != '/'&& *dstr != 0);
	*dstr = 0;
	const char* dstip = cstr;

	if (memcmp(srcip, anyStr, strlen(anyStr)) == 0)
	{
		rule.isSrc = false;
		rule.ip = inet_addr(dstip);
	}
	else
	{
		rule.isSrc = true;
		rule.ip = inet_addr(srcip);
	}

	//if (memcmp(dstip, anyStr, strlen(anyStr)) == 0)
	//{
	//	rule.minDstIP = 0;
	//	rule.maxDstIP = 0xffffffff;
	//}
	//else
	//{
	//	rule.minDstIP = inet_addr(dstip);
	//	rule.maxDstIP = rule.minDstIP + 1;
	//	rule.minDstIP -= 1;
	//}

	return true;
}

Binary PatternLoader::ptrn_str_to_bytes(const std::string & str) {
    Binary bytes;

    size_t strlen = str.length();
    for (size_t i = 0; i < strlen; ) {
        // handle binary data in hex form
        if (str[i] == '|') 
		{
            // find next '|' and extract the hex string
            size_t nextDelim = str.find('|', i + 1);
            const std::string& hexes = str.substr(i + 1, nextDelim - i - 1);

            // transform each char
            size_t idx = 0;
            while (idx < hexes.length()) 
			{
                if (hexes[idx] == ' ') {
                    ++idx;
                    continue;
                }
                bytes.push_back(cap_hex_to_byte(hexes.substr(idx, 2)));
                idx += 2;
            }

            // update index
            i = nextDelim + 1;
        }
        // normal character
        else 
		{
            bytes.push_back(str[i]);
            ++i;
        }
    }
    return bytes;
}
