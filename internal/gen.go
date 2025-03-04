package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -cflags "-I/usr/include/x86_64-linux-gnu" sampler_kern sampler_kern.c
