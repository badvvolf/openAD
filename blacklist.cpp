#include "blacklist.h"

bool Blacklist::addBlacklist(uint32_t ban_ip)
{
    net_rule_manager.addBlacklist(ban_ip);
}