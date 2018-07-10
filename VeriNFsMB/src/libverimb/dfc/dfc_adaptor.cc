#include "dfc_adaptor.h"

DFCAdaptor::DFCAdaptor() {
  m_dfc = DFC_New();
}

void DFCAdaptor::init(const PatternSet& patterns) {
  int numPtrn = patterns.size();
  for (int i = 0; i < numPtrn; ++i)
    DFC_AddPattern(m_dfc,
                   const_cast<Byte *>(patterns[i].data()),
                   patterns[i].size(), 1, i, i);

  DFC_Compile(m_dfc);
}

DFCAdaptor::~DFCAdaptor() {
    DFC_FreeStructure(m_dfc);
}

int match_action(void *, void *, int pid, void *, void *) {
    return 0;
}

void DFCAdaptor::process(uint16_t id, const unsigned char* payload, int length, std::string& ringer) 
{
    int resCount = DFC_Search(m_dfc, 
               id,
               const_cast<unsigned char*>(payload),
               length, 
               ringer,
               match_action, NULL);
	ringer.assign((char*)&resCount, sizeof(resCount));
}
