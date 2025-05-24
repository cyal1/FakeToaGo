package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go  -cc clang -target amd64 -cflags "-g -O2 -Wall -target bpf -D __TARGET_ARCH_amd64"  fakeip pbf/fakeip.bpf.c
