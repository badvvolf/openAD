
# Notice: the kbuilddir can be redefined on make cmdline
#kbuilddir ?= /lib/modules/$(shell uname -r)/build
#KERNEL=$(kbuilddir)

SOURCE := ./src
SOURCE_FIREWALL := $(SOURCE)/firewall
SOURCE_FRAMEWORK := $(SOURCE)/framework
SOURCE_TEST := ./test

HEADER := ./headers
HEADER_BPF := $(HEADER)/bpf


BUILD := ./build

all: firewall framework

firewall: firewall_ingress.o firewall_egress.o

firewall_ingress.o:
	clang -O2 -Wall -target bpf -I$(HEADER) -c $(SOURCE_FIREWALL)/ebpf_ingress.c -o $(BUILD)/firewall_ingress.o 

firewall_egress.o:
	clang -O2 -Wall -target bpf -I$(HEADER) -I$(HEADER)/iproute2 -c $(SOURCE_FIREWALL)/ebpf_egress.c -o $(BUILD)/firewall_egress.o 

framework: 
	g++ $(SOURCE_FRAMEWORK)/ebpfsuper.cpp $(SOURCE_FRAMEWORK)/ebpfloader.cpp $(SOURCE_FRAMEWORK)/netrulemanager.cpp \
	$(SOURCE_TEST)/test_netrulemanager.cpp $(SOURCE_FRAMEWORK)/bpf_load.o \
	-o $(BUILD)/main -I$(HEADER) -I$(HEADER_BPF) -lbpf -lelf -fPIC

clean_firewall:
	rm $(BUILD) *.o

clean_framework:
	rm $(BUILD) main

clean: clean_firewall clean_framework

