#include "network_manager.h"
#include "bpf.h"
#include "libbpf.h"
#include <errno.h>
#include <string.h>

using namespace std;

//if you already opened map, then just process
// if you didn't opened, open first.
// user don't mind if it's opened. it just automated


bool NetRuleManager::AddBlacklist(int32_t ban_ip)
{
    if(notopened)
        OpenMap("", (int32_t)MAPNUM::BLACKLIST);
    


}