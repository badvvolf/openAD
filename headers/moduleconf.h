#ifndef __MODULECONF_H
#define __MODULECONF_H

#include "configuration.h"
#include <cstdint>
#include <vector>
#include <string>

#include "logger.h"
#include "blacklist.h"
#include "portforward.h"


class ModuleConf : public Configuration {

private:

    Logger &logger;
    Blacklist &blacklist;
    Portforward &portforward;

    std::string totalConf;
    rapidjson::Document conf;

    void parse();

public:
    ModuleConf(Logger &, Blacklist &, Portforward &);
    
    //get conf from UI
    void getConf();
    
    
    //pass conf which this class got
    std::string getConfValueByKeys(std::vector<std::string>);

    int32_t getNetConf();
    void publish();


};





#endif