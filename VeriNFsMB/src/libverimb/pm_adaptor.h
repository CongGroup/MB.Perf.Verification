#ifndef PM_ADPATOR_H
#define PM_ADPATOR_H

#include <stdint.h>
#include <string>

#include "pattern_loader.h"

class PMAdaptor
{
public:
    PMAdaptor() {};
    ~PMAdaptor() {};

    virtual void init(const PatternSet& patterns) = 0;
    
    virtual void process(uint16_t id, const unsigned char* payload, int length, std::string& ringer) = 0;

    void turn_on_ringer();

    void turn_off_ringer();
};

#endif