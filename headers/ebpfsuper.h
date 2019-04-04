#ifndef __EBPFSUPER_H
#define __EBPFSUPER_H

#include <cstdint>
#include <string>
#include <map>

#ifndef BPF_FS_MAGIC
# define BPF_FS_MAGIC   0xcafe4a11
#endif

class EBPFSuper{

private: 

protected:

    //////////// map path <- read config file
    static std::map<std::string, std::string> map_path;
    static std::map<std::string, int32_t> fd_map_exported;

    static bool openExportedMap(std::string path, std::string mapname);
    static int checkMapPath(std::string path);

public:

    EBPFSuper();
    ~EBPFSuper();
};



#endif