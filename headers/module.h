#ifndef __MODULE_H
#define __MODULE_H

#include "blacklist.h"
#include "moduleconf.h"
#include "logger.h"
#include <string>

class Module {

    private:
        void openTCP();
        void openNetwork();
        
        // function pointer connecet_callback
        // function pointer receive_callback

    public:

        Blacklist blacklist;
        Logger logger;
        ModuleConf moduleconf;
        Portforward portforward;

        Module();
        void work();

        void setConf();
        std::string getModuleConf();

        void addNetConnectCallback();
        void addNetRecieveCallback();
        
        void addBlacklist(uint32_t);
        void subBlacklist(uint32_t);

        
        void netReceiveCallback(int32_t);
        
        

};

#endif