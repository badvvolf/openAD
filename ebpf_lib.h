
#ifdef __cplusplus
extern "C" {
#endif




int open_bpf_map(const char *file);
int add_blacklist(int fd, char *ip_string);





#ifdef __cplusplus
}
#endif