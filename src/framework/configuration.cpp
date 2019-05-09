#include "configuration.h"

void Configuration::parse()
{
    conf.Parse(totalConf.c_str());
}