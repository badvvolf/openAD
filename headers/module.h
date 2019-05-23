#ifndef __MODULE_H
#define __MODULE_H

#include "blacklist.h"
#include "moduleconf.h"
#include "logger.h"
#include <string>

typedef void (*funcptr_work)(Logger *, Blacklist *, Portforward *);

class Module {

    private:

    public:
        
        ModuleConf moduleconf;

        Blacklist *blacklist;
        Logger *logger;
        
        Portforward *portforward;


        funcptr_work workfunc = NULL;


        Module();
        void work(bool);
        void setWork(funcptr_work, Logger * , Blacklist *, Portforward * );

        void setConf(Logger *);
        void setConf(Blacklist *);
        void setConf(Portforward *);


        std::string getModuleConf(std::string);


};

#endif