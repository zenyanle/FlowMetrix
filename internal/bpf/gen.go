package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -cflags "-I/usr/include/x86_64-linux-gnu" -cc /usr/bin/clang-17 sampler_kern sampler_kern.c
