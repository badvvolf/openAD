#include "module.h"
#include "logger.h"
#include "blacklist.h"
#include "portforward.h"
#include <iostream>
#include <unistd.h>

void work(Logger *lg, Blacklist * bl, Portforward * pf);

int main()
{
    Module m;

    Logger l;
    m.setConf(&l);

    Portforward p;
    m.setConf(&p);

    funcptr_work fp = &work;
    
    m.setWork(fp, &l, NULL, &p);

    m.work();

}


void work(Logger *lg, Blacklist * bl, Portforward * pf)
{
    std::cout<<"test"<<std::endl;
    lg->add("123", "456");
    lg->publish();
    sleep(5);
}