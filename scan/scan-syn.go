package scan

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
	"github.com/mostlygeek/arp"
	"github.com/phayes/freeport"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"sync"
	"time"
)

//使用gopacket包使得go能够处理数据包

type SynScanner struct {
	timeout          time.Duration
	maxRoutines      int
	jobChan          chan hostJob
	ti               *TargetIterator
	serializeOptions gopacket.SerializeOptions
}

// NewSynScanner 传入迭代器,超时,并发数,返回一个syn扫描器
func NewSynScanner(ti *TargetIterator, timeout time.Duration, paralellism int) *SynScanner {
	return &SynScanner{
		timeout:     timeout,
		maxRoutines: paralellism,
		jobChan:     make(chan hostJob, paralellism),
		ti:          ti,
		serializeOptions: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
	}
}

//实现scanner接口

func (s SynScanner) Stop() {

}

// Start 就是开启消费者(数量等于输入的并发数量),不断获取job,执行扫描,并将结果返回
func (s SynScanner) Start() error {
	for i := 0; i < s.maxRoutines; i++ {
		go func() {
			for {
				job := <-s.jobChan
				if job.ports == nil || len(job.ports) == 0 { //TODO:什么时候ports会是nil?
					break
				}
				result, err := s.scanHost(job)
				if err != nil {
					log.Debugf("Error scanning host %s: %s", job.ip, err)
				}
				job.resultChan <- &result
				close(job.done) //释放
			}

		}()

	}
	return nil
}

//核心扫描逻辑
func (s *SynScanner) scanHost(job hostJob) (Result, error) {
	result := NewResult(job.ip)

	select {
	case <-job.ctx.Done():
		return result, nil
	default:

	}
	//-------------------------数据包操作--------------------------------
	router, err := routing.New()
	if err != nil {
		return result, err
	}

	networkInterface, gateway, srcIP, err := router.Route(job.ip)
	if err != nil {
		return result, err
	}

	handle, err := pcap.OpenLive(networkInterface.Name, 65535, true, pcap.BlockForever)
	if err != nil {
		return result, err
	}
	defer handle.Close()

	openChan := make(chan int) //这些Channel会附加到job中传递,
	closedChan := make(chan int)
	filteredChan := make(chan int)
	doneChan := make(chan struct{})

	start := time.Now()

	go func() { //汇总结果
		for {
			select {
			case open := <-openChan:
				if open == 0 { //收到零值说明已被关闭
					close(doneChan) //关闭donechan使得主G退出
					return
				}
				if result.Latency < 0 {
					result.Latency = time.Since(start)
				}
				for _, existing := range result.Open {
					if existing == open {
						continue
					}
				}
				result.Open = append(result.Open, open)
			case closed := <-closedChan:
				if result.Latency < 0 {
					result.Latency = time.Since(start)
				}
				for _, existing := range result.Closed {
					if existing == closed {
						continue
					}
				}
				result.Closed = append(result.Closed, closed)
			case filtered := <-filteredChan:
				if result.Latency < 0 {
					result.Latency = time.Since(start)
				}
				for _, existing := range result.Filtered {
					if existing == filtered {
						continue
					}
				}
				result.Filtered = append(result.Filtered, filtered)
			}
		}
	}()

	rawPort, err := freeport.GetFreePort() //获取一个空闲的端口
	if err != nil {
		return result, err
	}
	//根据IP 获取硬件MAC地址
	hwaddr, err := s.getHwAddr(job.ip, gateway, srcIP, networkInterface)
	if err != nil {
		return result, err
	}
	// Construct all the network layers we need.
	eth := layers.Ethernet{
		SrcMAC:       networkInterface.HardwareAddr,
		DstMAC:       hwaddr,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    job.ip,
		Version:  4,
		TTL:      255,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(rawPort),
		DstPort: 0,
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(&ip4)
	listenChan := make(chan struct{})

	ipFlow := gopacket.NewFlow(layers.EndpointIPv4, job.ip, srcIP)

	go func() {

		eth := &layers.Ethernet{}
		ip4 := &layers.IPv4{}
		tcp := &layers.TCP{}

		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, eth, ip4, tcp)

		for {

			select {
			case <-job.ctx.Done():
				break
			default:
			}

			// Read in the next packet.
			data, _, err := handle.ReadPacketData()
			if err == pcap.NextErrorTimeoutExpired {
				break
			} else if err == io.EOF {
				break
			} else if err != nil {
				// connection closed
				fmt.Printf("Packet read error: %s\n", err)
				continue
			}
			//解析返回的数据,判断端口状态
			decoded := []gopacket.LayerType{}
			if err := parser.DecodeLayers(data, &decoded); err != nil {
				continue
			}
			for _, layerType := range decoded {
				switch layerType {
				case layers.LayerTypeIPv4:
					if ip4.NetworkFlow() != ipFlow {
						continue
					}
				case layers.LayerTypeTCP:
					if tcp.DstPort != layers.TCPPort(rawPort) {
						continue
					} else if tcp.SYN && tcp.ACK {
						openChan <- int(tcp.SrcPort)
					} else if tcp.RST {
						closedChan <- int(tcp.SrcPort)
					}
				}
			}

		}

		close(listenChan)

	}()

	for _, port := range job.ports {
		tcp.DstPort = layers.TCPPort(port)
		_ = s.send(handle, &eth, &ip4, &tcp)
	}

	timer := time.AfterFunc(s.timeout, func() { handle.Close() })
	defer timer.Stop()

	<-listenChan

	close(openChan)
	<-doneChan

	return result, nil

}

// send sends the given layers as a single packet on the network.
func (s *SynScanner) send(handle *pcap.Handle, l ...gopacket.SerializableLayer) error {
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, s.serializeOptions, l...); err != nil {
		return err
	}
	return handle.WritePacketData(buf.Bytes())
}
func (s *SynScanner) getHwAddr(ip net.IP, gateway net.IP, srcIP net.IP, networkInterface *net.Interface) (net.HardwareAddr, error) {
	//先查看ARP中是否有缓存,有且正确的话直接返回
	macStr := arp.Search(ip.String())
	if macStr != "00:00:00:00:00:00" {
		if mac, err := net.ParseMAC(macStr); err == nil {
			return mac, nil
		}
	}

	arpDst := ip
	if gateway != nil {
		arpDst = gateway
	}

	handle, err := pcap.OpenLive(networkInterface.Name, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	start := time.Now()

	//发送ARP请求做准备
	eth := layers.Ethernet{
		SrcMAC:       networkInterface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(networkInterface.HardwareAddr),
		SourceProtAddress: []byte(srcIP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(arpDst),
	}
	buf := gopacket.NewSerializeBuffer()

	if err := gopacket.SerializeLayers(buf, s.serializeOptions, &eth, &arp); err != nil {
		return nil, err
	}
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return nil, err
	}

	for {
		if time.Since(start) > s.timeout {
			return nil, errors.New("timeout getting ARP reply")
		}
		data, _, err := handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			return nil, err
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			if net.IP(arp.SourceProtAddress).Equal(arpDst) {
				return net.HardwareAddr(arp.SourceHwAddress), nil
			}
		}

	}

}

func (s SynScanner) Scan(ctx context.Context, ports []int) ([]Result, error) {
	wg := &sync.WaitGroup{}
	resultChan := make(chan *Result)
	results := []Result{}
	doneChan := make(chan struct{})

	go func() {
		for {
			result := <-resultChan
			if result == nil {
				close(doneChan)
				break
			}
			results = append(results, *result)
		}
	}()

	for {
		ip, err := s.ti.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		select {
		case <-ctx.Done():
			break
		default:
		}

		wg.Add(1)
		tIP := make([]byte, len(ip))
		copy(tIP, ip)
		go func(host net.IP, ports []int, wg *sync.WaitGroup) {

			done := make(chan struct{})

			s.jobChan <- hostJob{
				resultChan: resultChan,
				ip:         host,
				ports:      ports,
				done:       done,
				ctx:        ctx,
			}

			<-done
			wg.Done()
		}(tIP, ports, wg)
	}

	wg.Wait()
	close(s.jobChan)
	close(resultChan)
	<-doneChan

	s.Stop()

	return results, nil
}

func (s SynScanner) OutPutReault(resul Result) {
	fmt.Println(resul.String())
}
