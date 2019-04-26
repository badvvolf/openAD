
# Notice: the kbuilddir can be redefined on make cmdline
#kbuilddir ?= /lib/modules/$(shell uname -r)/build
#KERNEL=$(kbuilddir)

SOURCE := ./src
BUILD := ./build

all : firewall.o

firewall.o:
	clang -O2 -Wall -target bpf -I./headers -I./headers/iproute2 -c $(SOURCE)/ebpf_firewall.c -o $(BUILD)/firewall.o 

clean:
	rm -f *.o

