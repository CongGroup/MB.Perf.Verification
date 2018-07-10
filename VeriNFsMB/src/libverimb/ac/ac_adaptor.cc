#include "ac_adaptor.h"

ACAdaptor::ACAdaptor()
{

}

ACAdaptor::~ACAdaptor()
{

}

void ACAdaptor::init(const PatternSet& patterns)
{
    int numPtrn = patterns.size();
    static std::string str;
    for (int i = 0; i < numPtrn; ++i) {
        str.assign((char *)patterns[i].data(), patterns[i].size());
        ac.insert(str);
    }
}

void ACAdaptor::process(uint16_t id, const unsigned char* payload, int length, std::string& ringer)
{
    static std::string str;
    str.assign((char *)payload, length);
    
    ac.parse_text(str, id, ringer);
}
