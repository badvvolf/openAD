#ifndef __MODULE_H
#define __MODULE_H

#include "blacklist.h"
#include "moduleconf.h"
#include "logger.h"


class Module {

    private:
        void openTCP();
        void openNetwork();
        
        // function pointer connecet_callback
        // function pointer receive_callback

    public:

        Module();
        Blacklist blacklist;
        Logger logger;
        ModuleConf moduleconf;

        void addNetConnectCallback();
        void addNetRecieveCallback();
        
        void addBlacklist(uint32_t);
        void addConfiguration();

        void netReceiveCallback(int32_t);
        
        void work();

};

#endif