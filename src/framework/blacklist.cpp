#include "blacklist.h"

bool Blacklist::addRule(uint32_t ip)
{

    //save to the blacklist list (DB..)


    //update map
    net_rule_manager.addBlacklist(ip);
}

bool Blacklist::subRule(uint32_t ip)
{
    //save to the blacklist list (DB..)

    net_rule_manager.subBlacklist(ip);
}