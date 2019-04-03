
#ifdef __cplusplus
extern "C" {
#endif




int open_bpf_map(const char *file);
int blacklist_modify(int fd, char *ip_string);





#ifdef __cplusplus
}
#endif