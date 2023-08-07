#obj-m += tcp_reno_verbose.o tcp_cubic_verbose.o tcp_bbr_verbose.o
obj-m += tcp_reno_verbose.o tcp_cubic_verbose.o tcp_cubic_ss.o

IDIR= /lib/modules/$(shell uname -r)/kernel/net/ipv4/
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules

install_vreno:
	install -v -m 644 tcp_reno_verbose.ko $(IDIR)
	depmod
	modprobe tcp_reno_verbose
	sysctl -w net.ipv4.tcp_allowed_congestion_control="$(shell sysctl net.ipv4.tcp_allowed_congestion_control -n) reno_verbose"

install_vreno_ss_init:
	install -v -m 644 tcp_cubic_verbose.ko $(IDIR)
	depmod
	modprobe tcp_reno_verbose initial_ssthresh=$(initial_ssthresh)
	sysctl -w net.ipv4.tcp_allowed_congestion_control="$(shell sysctl net.ipv4.tcp_allowed_congestion_control -n) reno_verbose"

install_vcubic:
	install -v -m 644 tcp_cubic_verbose.ko $(IDIR)
	depmod
	modprobe tcp_cubic_verbose
	sysctl -w net.ipv4.tcp_allowed_congestion_control="$(shell sysctl net.ipv4.tcp_allowed_congestion_control -n) cubic_verbose"

install_vcubic-ss:
	install -v -m 644 tcp_cubic_ss.ko $(IDIR)
	depmod
	modprobe tcp_cubic_ss
	sysctl -w net.ipv4.tcp_allowed_congestion_control="$(shell sysctl net.ipv4.tcp_allowed_congestion_control -n) cubic_ss"

install_vbbr:
	install -v -m 644 tcp_bbr_verbose.ko $(IDIR)
	depmod
	modprobe tcp_bbr_verbose
	sysctl -w net.ipv4.tcp_allowed_congestion_control="$(shell sysctl net.ipv4.tcp_allowed_congestion_control -n) bbr_verbose"

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -rf Module.markers modules.order Module.symvers tcp_reno_verbose.ko tcp_reno_verbose.mod.c tcp_reno_verbose.mod.o tcp_reno_verbose.o tcp_cubic_verbose.o tcp_cubic_verbose.mod.o tcp_cubic_verbose.mod.c tcp_cubic_verbose.ko

