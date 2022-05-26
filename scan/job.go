package scan

import (
	"context"
	"net"
)

//用于端口扫描
type portJob struct {
	ip net.IP
	//三个通道归类不同状态的端口
	port     int
	open     chan int
	closed   chan int
	filtered chan int
	done     chan struct{}   //信号通道
	ctx      context.Context //用于控制
}

//用于主机扫描
type hostJob struct {
	ip         net.IP
	ports      []int
	resultChan chan *Result
	done       chan struct{}
	ctx        context.Context
}
