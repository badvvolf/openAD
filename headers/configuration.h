#ifndef __CONFIGURATION_H
#define __CONFIGURATION_H
#include "rapidjson/document.h"     // rapidjson's DOM-style API
#include <string>

class Configuration {

protected:

    rapidjson::Document conf;

    void parse();
    std::string totalConf;

public:
        


};

//2^n
enum class SAVEPOINT{
    STDOUT = 0x00000001,
    STDERR = 0x00000002,
    FILE = 0x00000004,
    DB_MYSQL = 0x00000008


};



#endif
