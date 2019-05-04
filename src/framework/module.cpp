#include "module.h"
#include <iostream>

using namespace std;


// use try-catch!!!!!!!!!!!!!!!!!!


Module::Module() : blacklist(logger), moduleconf(logger, blacklist, portforward)
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

//get module specific conf
// json module:{}
std::string Module::getModuleConf()
{
    setConf();

}

// user call it first (need to... )
//need function to change conf....
void Module::setConf()
{

    //if no conf, get conf
    if(moduleconf.isSet())
        return;

    cout <<"Configuraation didn't set! You need to set configuration first" << endl;
    cout << "Wait to set configuration.." << endl;

    //wait for conf
    //this can be syn (blocked)
    moduleconf.getConf();

    moduleconf.publish();


}

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


