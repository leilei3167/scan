package scan

type PortState uint8

const (
	PortUnknown PortState = iota
	PortOpen
	PortClosed
	PortFiltered
)

var DefaultPorts []int

func init() {

	for port := range knownPorts { //初始化默认端口列表
		DefaultPorts = append(DefaultPorts, port)
	}
}

func DescribePort(port int) string { //返回端口的描述
	if s, ok := knownPorts[port]; ok {
		return s
	}

	return ""
}
