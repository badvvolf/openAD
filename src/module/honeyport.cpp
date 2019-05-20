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

    Blacklist b("ens33");
      
    // char * ip_string = "192.168.42.128";
    // uint32_t ip = inet_addr(ip_string);
    // b.addRule(ip);

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
    pf->addRule((uint16_t)12345, (uint16_t)12346);

}