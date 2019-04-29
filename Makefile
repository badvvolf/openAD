
# Notice: the kbuilddir can be redefined on make cmdline
#kbuilddir ?= /lib/modules/$(shell uname -r)/build
#KERNEL=$(kbuilddir)

SOURCE := ./src
BUILD := ./build

all : firewall.o egress.o

firewall.o:
	clang -O2 -Wall -target bpf -I./headers -c $(SOURCE)/ebpf_firewall.c -o $(BUILD)/firewall.o 

egress.o:
	clang -O2 -Wall -target bpf -I./headers -I./headers/iproute2 -c $(SOURCE)/egress.c -o $(BUILD)/egress.o 

clean:
	rm -f *.o

