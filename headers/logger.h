#ifndef __LOGGER_H
#define __LOGGER_H

#include <string>
#include "rapidjson/document.h"     // rapidjson's DOM-style API
#include "configuration.h"
#include <fstream>

#define DEFAULT_LOG_PATH "./log"

class Logger {

    private:

        rapidjson::Document log;
        rapidjson::Document::AllocatorType& alloc = log.GetAllocator();
        
        uint32_t savepoint = (uint32_t)SAVEPOINT::STDERR;
        
        std::fstream log_file;
        std::string log_path = DEFAULT_LOG_PATH;

    public:
        Logger();

        std::string getLogString();
        
        void add(std::string, std::string);
        void sub(std::string);
        void cleanBuf();
        void publish();
        void setConf(uint32_t, std::string);

};



#endif
