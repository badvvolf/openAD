
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

all: firewall framework core

firewall: firewall_ingress.o firewall_egress.o 

firewall_ingress.o:
	clang -O2 -Wall -target bpf -I$(HEADER) -c $(SOURCE_FIREWALL)/ebpf_ingress.c -o $(BUILD)/firewall_ingress.o 

firewall_egress.o:
	clang -O2 -Wall -target bpf -I$(HEADER) -I$(HEADER)/iproute2 -c $(SOURCE_FIREWALL)/ebpf_egress.c -o $(BUILD)/firewall_egress.o 

framework: 

	g++ -shared -fPIC -o $(BUILD)/libframework.so $(SOURCE_FRAMEWORK)/*.cpp $(SOURCE_FRAMEWORK)/bpf_load.o -I$(HEADER) -I$(HEADER_BPF) -lbpf -lelf -fPIC
	
	# g++ $(SOURCE_FRAMEWORK)/ebpfsuper.cpp $(SOURCE_FRAMEWORK)/ebpfloader.cpp $(SOURCE_FRAMEWORK)/netrulemanager.cpp \
	# $(SOURCE_TEST)/test_netrulemanager.cpp $(SOURCE_FRAMEWORK)/bpf_load.o \
	# -o $(BUILD)/main -I$(HEADER) -I$(HEADER_BPF) -lbpf -lelf -fPIC

	# g++ $(SOURCE_FRAMEWORK)/*.cpp $(SOURCE_FRAMEWORK)/bpf_load.o $(SOURCE_TEST)/test_module.cpp \
	# -o $(BUILD)/main_test -I$(HEADER) -I$(HEADER_BPF) -lbpf -lelf -fPIC

core : framework
	g++ -o $(BUILD)/core $(SOURCE)/core_main.cpp -lframework -I$(HEADER) -I$(HEADER_BPF) -L$(BUILD)

bpf_load.o:
	gcc $(SOURCE_FRAMEWORK)/bpf_load.c -o bpf_load.o -I$(HEADER) -I$(HEADER_BPF)

# test_loader:
# 	g++ $(SOURCE_FRAMEWORK)/*.cpp $(SOURCE_FRAMEWORK)/bpf_load.o $(SOURCE_TEST)/test_netrulemanager.cpp \
# 	-o $(BUILD)/main_test -I$(HEADER) -I$(HEADER_BPF) -lbpf -lelf -fPIC

test2:
	g++ -o $(BUILD)/test $(SOURCE_TEST)/test_module.cpp -lframework -I$(HEADER) -I$(HEADER_BPF) -L$(BUILD)


clean_firewall:
	rm $(BUILD)/*.o

clean_framework:
	rm $(BUILD)/libframework.so
	rm $(BUILD)/core

clean: clean_firewall clean_framework

