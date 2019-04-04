#include <cstdint>
#include <string>
#include <map>


class EBPFSuper{

private: 

   
protected:

    //////////// map path <- read config file
    static std::map<std::string, std::string> map_path;
    static std::map<std::string, int32_t> fd_map_exported;
    
    
public:

    EBPFSuper(){

        map_path.insert(make_pair("blacklist", "/sys/fs/bpf/blacklist"));

    };

    ~EBPFSuper(){};
    static bool OpenExportedMap(std::string path, struct bpf_map_data *map_data);
    static int bpf_fs_check_path(std::string path);

};

class EBPFLoader : public EBPFSuper{

private:
    std::string filepath_ebpf;
    std::string net_interface;
    static std::map<std::string, bool> map_exported;
    static std::map<std::string, int32_t> map_index; //to find fd in bpf_load.c
    

    void ExportMaps(void);

public:

    static void PreloadMapsViaFs(struct bpf_map_data *map_data, int32_t mapnum);

    EBPFLoader(std::string, std::string);
    void EBPFLoader::chown_maps(uid_t owner, gid_t group);

    int32_t Load();

};

