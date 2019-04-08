#ifndef __MODULECONF_H
#define __MODULECONF_H

#include "configuration.h"
#include <cstdint>

class ModuleConf : public Configuration {

private:

public:

    void getConf();
    int32_t getNetConf();


};


#endif