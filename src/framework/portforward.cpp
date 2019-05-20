#include "portforward.h"

Portforward::Portforward(std::string interface) : net_rule_manager(interface)
{

}

bool Portforward::addRule(uint16_t outport, uint16_t inport)
{
    //save to the portforward list (DB..)

    //update map
    net_rule_manager.addPortForward(outport, inport);
}

bool Portforward::subRule(uint16_t outport, uint16_t inport)
{
    //save to the portforward list (DB..)

    net_rule_manager.subPortForward(outport, inport);
}