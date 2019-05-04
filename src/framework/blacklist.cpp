#include "blacklist.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

Blacklist::Blacklist(Logger & log):logger(log){};

bool Blacklist::addRule(uint32_t ip)
{

    if(net_rule_manager.addBlacklist(ip))
    {    
        saveBackup(ip);

        struct in_addr addr = {ip};
        logger.add("blacklist_add", inet_ntoa(addr));
    }
}

bool Blacklist::subRule(uint32_t ip)
{
    if(net_rule_manager.subBlacklist(ip))
    {
        removeBackup(ip);

        struct in_addr addr = {ip};
        logger.add("blacklist_sub", inet_ntoa(addr));
    }
}


void Blacklist::saveBackup(uint32_t ip)
{
    if(savepoint == (uint32_t)SAVEPOINT::FILE)
    {

    }

}



void Blacklist::removeBackup(uint32_t ip)
{




}



void Blacklist::setConf(uint32_t sp)
{
    savepoint = sp;
}