package bpf

import (
	"FlowMetrix/pkg/logger"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"net"
	"os"
)

type SamplerKernObjectsWrapper struct {
	objs sampler_kernObjects
}

func (s *SamplerKernObjectsWrapper) Close() {
	err := s.objs.Close()
	if err != nil {
		logger.Panic(err)
	}
}

func NewPerfReader() (*perf.Reader, link.Link, *SamplerKernObjectsWrapper) {
	objs := sampler_kernObjects{}
	if err := loadSampler_kernObjects(&objs, nil); err != nil {
		logger.Fatalf("Loading objects: %v", err)
	}
	interfaceName := "ens33"
	// interfaceName := config.Get("config.ifname").(string)

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		logger.Fatalf("Finding interface %s: %v", interfaceName, err)
	}

	// 附加XDP程序到网络接口
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.Sampler,
		Interface: iface.Index,
	})
	if err != nil {
		logger.Fatalf("Attaching XDP: %v", err)
	}
	// defer xdpLink.Close()

	// 创建perf reader
	rd, err := perf.NewReader(objs.Events, os.Getpagesize()*128)
	if err != nil {
		logger.Fatalf("Creating perf reader: %v", err)
	}
	return rd, xdpLink, &SamplerKernObjectsWrapper{objs: objs}
}
