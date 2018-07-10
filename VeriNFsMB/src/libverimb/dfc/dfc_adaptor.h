#ifndef DFC_ADPATOR_H
#define DFC_ADPATOR_H

#include "dfc.h"
#include "../pm_adaptor.h"

class DFCAdaptor : public PMAdaptor
{
 public:
    
  DFCAdaptor();

  ~DFCAdaptor();

  void init(const PatternSet& patterns);
  
  void process(uint16_t id, const unsigned char* payload, int length, std::string& ringer);

 private:
  DFC_STRUCTURE* m_dfc;
};

#endif