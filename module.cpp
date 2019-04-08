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
    blacklist.addBlacklist(ip);
}


void Module::work()
{
    //if no conf, get conf
    if(!moduleconf.isSet())
    {
        cout <<"Configuraation not set,,, You need to set configuration first" << endl;
        cout << "Wait for conf by your way.." << endl;
        //wait for conf
        //this can be syn (blocked)
        moduleconf.getConf();
    }

    //open server if it needs ..
    openNetwork();

}

//asyn server -> tcp connect -> callNetworkCallback with connect_fd
//use opensource library - asyn c++ socket programming..


void Module::openTCP()
{


}


// user call it first (need to... )
void Module::addConfiguration()
{

    //conf
    moduleconf.getConf();
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


