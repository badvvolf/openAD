/*  Copyright(c) 2019 kjkjk1178.
 *  Copyright(c) 2017 Jesper Dangaard Brouer, Red Hat, Inc.
 *  Copyright(c) 2017 Andy Gospodarek, Broadcom Limited, Inc.
 */
#include "ebpfsuper.h"
//#include "libbpf.h"
#include "bpf_load.h"
#include <string.h>
#include <iostream>
#include <stdlib.h>
#include <errno.h>


#include <sys/statfs.h>
#include <libgen.h>

using namespace std;

std::map<std::string, std::string> EBPFSuper::map_path;
std::map<std::string, int32_t> EBPFSuper::fd_map_exported;


EBPFSuper::EBPFSuper()
{
    map_path["blacklist"] = "/sys/fs/bpf/blacklist";

}

//open exported map
bool EBPFSuper::openExportedMap(string path, struct bpf_map_data *map_data)
{
    if (checkMapPath(path) < 0) {
        exit(-1);
    }
    int32_t fd = bpf_obj_get(path.c_str());

    //if not exported
    if (fd < 0) {
        printf("ERR: Failed to open bpf map file:%s err(%d):%s\n",
                path.c_str(), errno, strerror(errno));
        return false;
    }
    
    fd_map_exported[map_data->name] =  fd;

    return true;
}

int EBPFSuper::checkMapPath(string path)
{
    struct statfs st_fs;
    char *dname, *dir;
    int err = 0;

    if (path == "")
        return -EINVAL;

    dname = strdup(path.c_str());
    if (dname == NULL)
        return -ENOMEM;

    dir = dirname(dname);
    if (statfs(dir, &st_fs)) {
        fprintf(stderr, "ERR: failed to statfs %s: (%d)%s\n",
            dir, errno, strerror(errno));
        err = -errno;
    }
    free(dname);

    if (!err && st_fs.f_type != BPF_FS_MAGIC) {
        fprintf(stderr,
                "ERR: specified path %s is not on BPF FS\n\n"
                " You need to mount the BPF filesystem type like:\n"
                "  mount -t bpf bpf /sys/fs/bpf/\n\n",
                path);
        err = -EINVAL;
    }

  return err;
}




