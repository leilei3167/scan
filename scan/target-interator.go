package scan

import (
	"fmt"
	"io"
	"net"
)

type TargetIterator struct {
	target string
	isCIDR bool
	index  int
	ip     net.IP     //net包中的IP,是一个字节切片,可以是IPv4 IPv6
	ipnet  *net.IPNet //包含IP和掩码,代表的是真正的IP地址
}

// NewTargetInteractor 127.0.0.1/24 ->IP:127.0.0.0 ipnet(127.0.0.0,掩码)
func NewTargetInteractor(target string) *TargetIterator {
	//ip是/前的部分,ipnet是包含该段ip的起始,以及一个掩码
	ip, ipnet, err := net.ParseCIDR(target)

	ti := &TargetIterator{
		target: target,
		isCIDR: err == nil, //看是否成功解析
	}

	if ti.isCIDR { //如果是CIDR
		ti.ip = ip.Mask(ipnet.Mask) //将ipnet的掩码还原成ip
		ti.ipnet = ipnet
	}
	return ti
}

func (ti *TargetIterator) Next() (net.IP, error) {
	ti.index++
	ip, err := ti.get()
	if err != nil {
		return ip, err
	}
	ti.incrementIP()
	return ip, nil
}

func (ti *TargetIterator) get() (net.IP, error) {
	//如果不是CIDR地址,则按照普通的IP进行解析
	if !ti.isCIDR {
		if ti.index > 1 {
			return nil, io.EOF
		}
		//解析IP是否正确,ip不正确,则可能是域名,解析域名成功返回第一个结果
		if ip := net.ParseIP(ti.target); ip != nil {
			return ip, nil
		} else if ips, err := net.LookupIP(ti.target); err == nil {
			if len(ips) == 0 {
				return nil, fmt.Errorf("Lookup failed: %v", ti.target)
			}
			return ips[0], nil

		} else {
			return nil, err
		}
	}

	//如果是CIDR
	if ti.ipnet.Contains(ti.ip) { //判断ip是否是在范围之内
		tIP := make([]byte, len(ti.ip))
		copy(tIP, ti.ip)
		return tIP, nil
	}
	return nil, io.EOF

}

func (ti *TargetIterator) incrementIP() {
	for j := len(ti.ip) - 1; j >= 0; j-- {
		ti.ip[j]++
		if ti.ip[j] > 0 {
			break
		}
	}
}
