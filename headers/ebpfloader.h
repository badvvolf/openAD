#ifndef __EBPFLOADER_H
#define __EBPFLOADER_H

#include "ebpfsuper.h"
#include "epbf_firewall.h"

class EBPFLoader : public EBPFSuper{

private:
    static std::string filepath_ebpf;
    static std::map<std::string, bool> map_exported;
    static std::map<std::string, int32_t> map_index; //to find fd in bpf_load.c
    
    static void preloadMapsViaFs(struct bpf_map_data *map_data, int32_t mapnum);
    void exportMaps(void);
    void chownExportedMaps(uid_t owner, gid_t group);

public:

    EBPFLoader(std::string, std::string);
    ~EBPFLoader();

    int32_t load();
};

#endif