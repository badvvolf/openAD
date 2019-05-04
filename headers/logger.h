#ifndef __LOGGER_H
#define __LOGGER_H

#include <string>
#include "rapidjson/document.h"     // rapidjson's DOM-style API
#include "configuration.h"

class Logger {

    private:

        rapidjson::Document log;
        rapidjson::Document::AllocatorType& alloc = log.GetAllocator();
        uint32_t savepoint = (uint32_t)SAVEPOINT::STDERR;

    public:
        Logger();

        std::string getLogString();
        
        void add(std::string, std::string);


        void sub(std::string);
        void cleanBuf();
        void publish();
        void setConf(uint32_t);

};



#endif
