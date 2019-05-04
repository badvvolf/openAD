#include "moduleconf.h"
#include "rapidjson/prettywriter.h" // for stringify JSON
#include <iostream>


using namespace std;

ModuleConf::ModuleConf(Logger &log, Blacklist &bl, Portforward &pf) 
                        :logger(log), blacklist(bl), portforward(pf)
{
    conf.SetObject();
}

void ModuleConf::getConf()
{
    //get conf from UI
    totalConf =  "{\"conf\":{\"log\":{\"sp\":1},\"bl\":{\"sp\":1},\"pf\":{\"sp\":1},\"module\":{\"hello\":\"hi\"}}}";

    parse();
}


std::string ModuleConf::getConfValueByKeys(vector<string> keys)
{
    //conf.
   
    
}


int32_t ModuleConf::getNetConf()
{

    return 1;

}

void ModuleConf::parse()
{
    conf.Parse(totalConf.c_str());
}



void ModuleConf::publish()
{
    cout << "test "  << conf["conf"]["module"]["hello"].GetString()<<endl;

    uint32_t logger_savepoint = conf["conf"]["log"]["sp"].GetInt();
    cout << logger_savepoint << endl;
    logger.setConf(logger_savepoint);



    isConfigured = true;
}

