#include "module.h"
#include "logger.h"

int main()
{
     Module m;
     m.work();
    // m.addBlacklist(1);
    
    // Logger l;

    Logger l;
    m.setConf(&l);

    l.add("1","2");
    l.publish();
    
    Blacklist bl;
    m.setConf(&bl);

    bl.addRule(1);
    

}