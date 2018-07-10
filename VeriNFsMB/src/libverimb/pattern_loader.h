#ifndef PATTERNLOADER_H
#define PATTERNLOADER_H

#include <string>
#include <vector>
#include "veri_header.h"

typedef uint8_t Byte;
typedef std::vector<Byte> Binary;
typedef std::vector<Binary> PatternSet;

class PatternLoader {
public:
    static void load_pattern_file(const char* file, PatternSet& ptnSet);
	static void load_firewall_file(const char* file, std::vector<fwRule>& ruleSet);
private:
    static char cap_hex_to_byte(const std::string& hex);

	static bool rule_str_to_rule(const std::string & str, fwRule& rule);

    static Binary ptrn_str_to_bytes(const std::string& str);
};

#endif