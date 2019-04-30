#include "blacklist.h"

bool Blacklist::addBlacklist(uint32_t ban_ip)
{

    //save to the blacklist list (DB..)


    //update map
    net_rule_manager.addBlacklist(ban_ip);
}