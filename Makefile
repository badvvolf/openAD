
# Notice: the kbuilddir can be redefined on make cmdline
#kbuilddir ?= /lib/modules/$(shell uname -r)/build
#KERNEL=$(kbuilddir)

SOURCE := ./src
BUILD := ./build

all : firewall_ingress.o firewall_egress.o

firewall_ingress.o:
	clang -O2 -Wall -target bpf -I./headers -c $(SOURCE)/ebpf_ingress.c -o $(BUILD)/firewall_ingress.o 

firewall_egress.o:
	clang -O2 -Wall -target bpf -I./headers -I./headers/iproute2 -c $(SOURCE)/ebpf_egress.c -o $(BUILD)/firewall_egress.o 

clean:
	rm -f *.o

