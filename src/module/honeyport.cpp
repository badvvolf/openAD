#include "module.h"
#include "logger.h"
#include "blacklist.h"
#include "portforward.h"
#include <iostream>
#include <unistd.h>
#include "netrulemanager.h"
#include <arpa/inet.h>

void work(Logger *lg, Blacklist * bl, Portforward * pf);

int main()
{
    Module m;

    Logger l;
    m.setConf(&l);

    Portforward p("ens33");
    m.setConf(&p);

    // get honeyport's setting
    // it's dictionary, you can get by key

    funcptr_work fp = &work;
    m.setWork(fp, &l, NULL, &p);

    m.work(false);
}

//with module setting....
void work(Logger *lg, Blacklist * bl, Portforward * pf)
{
    //set port by setting
    pf->addRule((uint16_t)22, (uint16_t)2222);

    //for spidertrap
    pf->addRule((uint16_t)80, (uint16_t)4444);

}