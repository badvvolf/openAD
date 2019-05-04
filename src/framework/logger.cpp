#include "logger.h"


#include "rapidjson/prettywriter.h" // for stringify JSON
#include <iostream>

using namespace std;
//using namespace rapidjson;

//get module info and get name of module
Logger::Logger()
{
    log.SetObject();
}


void Logger::add(string attribute, string value)
{
    rapidjson::Value attr;
    rapidjson::Value val;

    attr.SetString(attribute.c_str(), alloc);
    val.SetString(value.c_str(), alloc);

	log.AddMember(attr, val, alloc);
}



void Logger::sub(string attribute)
{
    rapidjson::Value attr;
    attr.SetString(attribute.c_str(), alloc);


    //there is EraseMember function .. see the difference
    log.RemoveMember(attr);
}

void Logger::cleanBuf()
{
    log.RemoveAllMembers();
}


string Logger::getLogString()
{
	rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);

    log.Accept(writer);

	return buffer.GetString();
}


void Logger::publish()
{
    string logstr = getLogString();

    //publish by config
    if(savepoint & (uint32_t)SAVEPOINT::STDOUT)
        cout << logstr << endl;
    if(savepoint & (uint32_t)SAVEPOINT::STDERR)
        cerr <<  logstr << endl;

    cleanBuf();

}

void Logger::setConf(uint32_t sp)
{
    savepoint = sp;
}


