package scan

import (
	"context"
	"fmt"
	"net"
	"time"
)

// Scanner 因为有多种的扫描器,所以使用接口来定义扫描器的行为
type Scanner interface {
	Stop()                                                   //可以停止
	Start() error                                            //可以开始
	Scan(ctx context.Context, ports []int) ([]Result, error) //扫描需要一个ctx 端口,返回结果或者错误
	OutPutReault(resul Result)                               //对外输出结果
}

type Result struct {
	Host net.IP
	//三种状态,开启,关闭,过滤
	Open     []int
	Closed   []int
	Filtered []int

	Manufacturer string        //?
	Mac          string        //Mac地址
	Latency      time.Duration //连接延迟
	Name         string
}

func NewResult(host net.IP) Result { //初始化
	return Result{
		Host:     host,
		Open:     []int{},
		Closed:   []int{},
		Filtered: []int{},
		Latency:  -1,
	}
}

func (r Result) IsHostUp() bool {
	return r.Latency > -1 //当主机存活时会修改默认值-1
}

//实现Stringer接口,自定义打印Result!
func (r Result) String() string {
	text := fmt.Sprintf("Scan result for %s:\n", r.Host.String()) //调用IP的String方法打印成字符串
	if r.IsHostUp() {
		//一步一步组合text
		text = fmt.Sprintf("%v\tHost is up with latency %v\n", text, r.Latency.String())
	} else {
		text = fmt.Sprintf("%v\tHost is down!", text)
	}
	if len(r.Open) > 0 {
		text = fmt.Sprintf("%s\t%s\t%s\t%s\t\n",
			text, "PORT", "STATE", "SERVICE")
	}

	for _, port := range r.Open {
		text = fmt.Sprintf(
			"%s\t\t%s\t\t%s\t\t%s\n",
			text,
			pad(fmt.Sprintf("%d/tcp", port), 10), // 8080/tcp
			pad("OPEN", 10),
			DescribePort(port), //TODO:从一个已知的端口详情map中返回描述
		)
	}
	return text

}

//填充空格直到达到指定的长度
func pad(input string, length int) string {
	for len(input) < length {
		input += " "
	}
	return input
}
