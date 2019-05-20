#include "module.h"
#include "logger.h"
#include "blacklist.h"
#include "portforward.h"
#include <iostream>


void work(Logger *lg, Blacklist * bl, Portforward * pf);

int main()
{
    Module m;

    Logger l;
    m.setConf(&l);

    // Portforward p;
    // m.setConf(&p);
    
    Blacklist b;
    m.setConf(&b);

    funcptr_work fp = &work;
    
   // m.setWork(fp, &l, &b, &p);

}


void work(Logger *lg, Blacklist * bl, Portforward * pf)
{
    std::cout<<"test"<<std::endl;
}