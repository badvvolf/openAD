#include "moduleconf.h"
#include "rapidjson/prettywriter.h" // for stringify JSON
#include <iostream>


using namespace std;

ModuleConf::ModuleConf()
{
    conf.SetObject();
}


void ModuleConf::getConf()
{
    //get conf from UI
    totalConf =  "{\"conf\":{\"log\":{\"sp\":4,\"lp\":\"\"},\"bl\":{\"sp\":4,\"bp\":\"\",\"logset\":true,\"log\":{\"sp\":4,\"lp\":\"./log\"}},\"pf\":{\"sp\":1},\"module\":{\"hello\":\"hi\",\"asd\":\"3\"}}}";

    parse();
}


std::string ModuleConf::getConfValueByKey(std::string key)
{
    //conf
    return conf["conf"]["module"][key.c_str()].GetString();
}


int32_t ModuleConf::getNetConf()
{
    
    return 1;

}



// return module's conf -> if you input key list, it returns value?? -> what if it's array or subtree?
std::string ModuleConf::getModuleConf()
{
    // rapidjson::Value::MemberIterator itr;
    // for ( itr= conf["conf"]["module"].MemberBegin(); itr !=  conf["conf"]["module"].MemberEnd(); ++itr)
    // {
    //     printf("Type of member %s is %s %p\n",
    //         itr->name.GetString(), itr->value.GetString(), itr);
    // }
    // printf("???? %p\n", itr);


}

void ModuleConf::publishConf(Logger *logger)
{
    uint32_t logger_savepoint = conf["conf"]["log"]["sp"].GetInt();
    std::string log_path =  conf["conf"]["log"]["lp"].GetString();
    logger->setConf(logger_savepoint, log_path);
}


void ModuleConf::publishConf(Blacklist *blacklist)
{   
    uint32_t black_savepoint = conf["conf"]["bl"]["sp"].GetInt();
    std::string black_backup_path = conf["conf"]["bl"]["bp"].GetString();

    bool logset = conf["conf"]["bl"]["logset"].GetBool();
    uint32_t black_log_savepoint = conf["conf"]["bl"]["log"]["sp"].GetInt();
    std::string black_log_path = conf["conf"]["bl"]["log"]["lp"].GetString();

    blacklist->setConf(black_savepoint, black_backup_path, logset, black_log_savepoint, black_log_path);
}

void ModuleConf::publishConf(Portforward * portforward)
{


}
