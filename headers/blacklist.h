#ifndef __BLACKLIST_H
#define __BLACKLIST_H

#include "netrulemanager.h"
#include "configuration.h"
#include "logger.h"
#include <fstream>

#define DEFAULT_BLACK_BACKUP_PATH "./blacklist"

class Blacklist {

private: 
    NetRuleManager net_rule_manager;
    uint32_t savepoint = (uint32_t)SAVEPOINT::FILE;

    Logger logger;
    bool useLogger = true;

    std::fstream backup_file;
    std::string backup_file_path = DEFAULT_BLACK_BACKUP_PATH;
    
    void saveBackup(uint32_t);
    void removeBackup(uint32_t);

public:

    Blacklist();

    bool addRule(uint32_t);
    bool subRule(uint32_t);
    void setConf(uint32_t, std::string, bool, uint32_t, std::string);  

    bool isLoggerSet();
    void setLogger();
    void unsetLogger();

};

#endif