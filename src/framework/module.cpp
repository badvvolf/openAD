#include "module.h"
#include <iostream>

using namespace std;


// use try-catch!!!!!!!!!!!!!!!!!!


Module::Module()
{
    //get configuration and spread it
    //use moduleconf's method

}


void Module::setWork(funcptr_work ptr, Logger * lg, Blacklist *bl, Portforward * pf)
{
    workfunc = ptr;
    logger = lg;
    blacklist = bl;
    portforward = pf;
}



void Module::work()
{
    while(1)
    {
        workfunc(logger, blacklist, portforward);
    }
}

//asyn server -> tcp connect -> callNetworkCallback with connect_fd
//use opensource library - asyn c++ socket programming..


//get module specific conf
// json module:{}
std::string Module::getModuleConf()
{
   
}

//need function to change conf....
void Module::setConf(Logger *logger)
{
    ModuleConf conf;

    cout << "Wait to set configuration.." << endl;

    //wait for conf
    //this can be syn (blocked)
    conf.getConf();

    conf.publishConf(logger);
}

void Module::setConf(Blacklist *blacklist)
{
    ModuleConf conf;

    cout << "Wait to set configuration.." << endl;

    conf.getConf();
    conf.publishConf(blacklist);
}

void Module::setConf(Portforward *portforward)
{
    ModuleConf conf;

    cout << "Wait to set configuration.." << endl;

    conf.getConf();
    conf.publishConf(portforward);
}

