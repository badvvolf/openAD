#include "blacklist.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fstream>

Blacklist::Blacklist(){}

bool Blacklist::isLoggerSet()
{
    return useLogger;
}

void Blacklist::setLogger()
{
    useLogger = true;
}
void Blacklist::unsetLogger()
{
    useLogger = false;
}

bool Blacklist::addRule(uint32_t ip)
{
    if(net_rule_manager.addBlacklist(ip))
    {    
        saveBackup(ip);

        if(isLoggerSet())
        {
            struct in_addr addr = {ip};
            logger.add("blacklist_add", inet_ntoa(addr));
            logger.publish();
        }
    }
}

bool Blacklist::subRule(uint32_t ip)
{
    if(net_rule_manager.subBlacklist(ip))
    {
        removeBackup(ip);

        if(isLoggerSet())
        {
            struct in_addr addr = {ip};
            logger.add("blacklist_sub", inet_ntoa(addr));
            logger.publish();
        }
    }
}


void Blacklist::saveBackup(uint32_t ip)
{
    struct in_addr addr = {ip};

    if(savepoint & (uint32_t)SAVEPOINT::FILE)
    {
        if(!backup_file.is_open())
        {
            backup_file.open(backup_file_path, std::fstream::in | std::fstream::out | std::fstream::app);
            if(!backup_file.is_open())
            {
                printf("blacklist backup file open error\n");
                return;
            }
        }

        backup_file << inet_ntoa(addr) << std::endl;
    }

}




void Blacklist::removeBackup(uint32_t ip)
{




}


void Blacklist::setConf(uint32_t bsp, std::string bp, bool logset, uint32_t lsp, std::string lp)
{
    savepoint = bsp;
    if(savepoint & (uint32_t)SAVEPOINT::FILE)
    {
        if(bp != "")
           backup_file_path = bp;
        else
            backup_file_path = DEFAULT_BLACK_BACKUP_PATH;
    }
    
    useLogger = logset;

    if(isLoggerSet())
        logger.setConf(lsp, lp);
}