#include "module.h"
#include <iostream>

using namespace std;


// use try-catch!!!!!!!!!!!!!!!!!!


Module::Module()
{
    //get configuration and spread it
    //use moduleconf's method

}

// register function pointer...
void Module::addNetConnectCallback()
{
    //register user funtion
}

void Module::addNetRecieveCallback()
{

    
}

void Module::addBlacklist(uint32_t ip)
{
    blacklist.addRule(ip);
}

void Module::subBlacklist(uint32_t ip)
{
    blacklist.subRule(ip);
}



void Module::work()
{
    setConf();
    
    //open server if it needs ..
    //openNetwork();

}

//asyn server -> tcp connect -> callNetworkCallback with connect_fd
//use opensource library - asyn c++ socket programming..


void Module::openTCP()
{


}


void Module::setConf()
{

    
}

//get module specific conf
// json module:{}
std::string Module::getModuleConf()
{
    setConf();

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

// void Module::setConf(Portforward *portforward)
// {
//     ModuleConf conf;

//     cout << "Wait to set configuration.." << endl;

//     conf.getConf();
//     conf.publishConf(portforward);
// }




void Module::openNetwork()
{
    //use configuration 
    switch (moduleconf.getNetConf())
    {
    case 0:
        openTCP();
        break;

    default:
        return;
        break;
    }

}


