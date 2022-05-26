package scan

import (
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ConnectScanner 是TCP扫描器
type ConnectScanner struct {
	timeout     time.Duration
	maxRoutines int             //协程数量
	jobChan     chan portJob    //portJob应该是所有扫描器通用的
	ti          *TargetIterator //迭代器 包含目标ip
}

// NewConnectScanner 创建一个TCP扫描器,传入解析后的目标,连接延迟,并发数量
func NewConnectScanner(ti *TargetIterator, timeout time.Duration, paralellism int) *ConnectScanner {
	return &ConnectScanner{
		timeout:     timeout,
		maxRoutines: paralellism,
		jobChan:     make(chan portJob, paralellism), //jobChan的容量和G的数量相同
		ti:          ti,
	}
}

// Start 实际上是消费者,获取从Scan()中生产的任务,并执行扫描,将结果分类传回对应的Chan,由Scan汇总返回
func (c *ConnectScanner) Start() error {
	//开启协程,不断的获取job,直到端口为0
	for i := 0; i < c.maxRoutines; i++ { //限制的是消费者的数量,永远只会有固定数量的文件操作符
		go func() {
			for {
				job := <-c.jobChan //在root执行了Scan前会阻塞在此,因为通道中没有数据,任务由Scan来生产
				if job.port == 0 {
					break
				}
				select {
				case <-job.ctx.Done(): //收到关闭请求将当前job的信号通道关闭
					close(job.done)
					return
				default:
					//预留一个default防止永久阻塞
				}

				//开始扫描,并获取结果,根据状态分类
				if state, err := c.scanPort(job.ip, job.port); err == nil {
					switch state {
					case PortOpen:
						job.open <- job.port
					case PortClosed:
						job.closed <- job.port
					case PortFiltered:
						job.filtered <- job.port
						//TODO:PortUnknown
					}
				}
				close(job.done) //标记为已完成
			}
		}()
	}
	return nil
}

// Scan 利用Channel关闭后读取会读出零值的特性,实现退出感知
func (c *ConnectScanner) Scan(ctx context.Context, ports []int) ([]Result, error) {
	wg := &sync.WaitGroup{}

	resultChan := make(chan *Result)
	results := []Result{}
	doneChan := make(chan struct{})

	go func() { //收集结果
		for {
			result := <-resultChan //如果resultChan收到零值则说明被关闭,执行推出
			if result == nil {
				close(doneChan)
				break
			}
			results = append(results, *result)
		}
	}()

	for { //用迭代器不断生成IP,没有做并发控制,ip数量超大的话?IP数量可能超大,但是消费者的数量是一定的,不会太多操作符
		//每一个IP都要构建一个结果,不适用于大量ip扫描
		//此处是每解析一个IP就发送下一步
		ip, err := c.ti.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		wg.Add(1)
		tIP := make([]byte, len(ip))
		copy(tIP, ip) //防止浅拷贝将ip传入
		//每一个IP开一个携程,每个ip的每个端口也会开携程,乘积关系,如1万个ip每个扫10个端口,将产生10万个携程
		go func(ip net.IP, ports []int, wg2 *sync.WaitGroup) {
			r := c.scanHost(ctx, ip, ports)
			resultChan <- &r
			wg2.Done()
		}(tIP, ports, wg)

		_ = ip
	}

	wg.Wait() //所有任务执行完毕之前阻塞在此
	close(resultChan)
	close(c.jobChan)
	<-doneChan
	return results, nil

}

func (c *ConnectScanner) OutPutReault(result Result) {
	fmt.Println(result.String()) //用Result的String()方法来格式化打印
}

func (c *ConnectScanner) Stop() {
	//暂时不用
}

//发起tcp连接,并分类
func (c *ConnectScanner) scanPort(target net.IP, port int) (PortState, error) {

	log.Debugf("开始扫描%s:%s", target.String(),
		strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", target.String(),
		strconv.Itoa(port)), c.timeout)
	if err != nil {
		log.Debugf("%s:%s :连接失败:%v", target.String(),
			strconv.Itoa(port), err)
		if strings.Contains(err.Error(), "refused") {
			return PortClosed, nil
		}
		return PortUnknown, err
	}
	conn.Close()
	log.Debugf("%s:%s is OPEN!", target.String(),
		strconv.Itoa(port))
	return PortOpen, err
}

//解析ip,生成构造job,并最终汇总结果返回
func (c *ConnectScanner) scanHost(ctx context.Context, host net.IP, ports []int) Result {
	wg := &sync.WaitGroup{}
	result := NewResult(host) //初始化一个结果

	//结果收集
	openChan := make(chan int)
	closedChan := make(chan int)
	filteredChan := make(chan int)
	doneChan := make(chan struct{})

	startTime := time.Now()

	go func() { //单独开协程收集结果
		for {
			select {
			case open := <-openChan:
				if open == 0 { //说明所有的任务已被处理完毕
					close(doneChan)
					return
				}
				if result.Latency < 0 { //记录第一次返回结果的时间,和开始的时间的差值,从而计算出连接花费的时间
					result.Latency = time.Since(startTime)
				}
				result.Open = append(result.Open, open)
			case closed := <-closedChan:
				if result.Latency < 0 {
					result.Latency = time.Since(startTime)
				}
				result.Closed = append(result.Closed, closed)
			case filtered := <-filteredChan:
				if result.Latency < 0 {
					result.Latency = time.Since(startTime)
				}
				result.Filtered = append(result.Filtered, filtered)
			}
		}
	}()

	for _, port := range ports { //并发生产任务,多少个端口就开多少个协程
		wg.Add(1)

		go func(p int, wg2 *sync.WaitGroup) {
			done := make(chan struct{})

			c.jobChan <- portJob{
				open:     openChan,
				closed:   closedChan,
				filtered: filteredChan,
				ip:       host,
				port:     p,
				done:     done, //每个协程单独创建的,在被消费之后会被释放
				ctx:      ctx,
			}
			<-done //阻塞直到这个任务被消费(扫描完毕会被关闭,取出0值解除阻塞)
			wg2.Done()
		}(port, wg)
	}

	wg.Wait()
	//解除阻塞后说明所有的任务被处理完毕,可以关闭并返回结果
	close(openChan) //关闭后 收集结果的Chan将接收到零值
	<-doneChan      //读出零值后,收集Chan也会关闭doneChan,确保其关闭后这里才会解除阻塞
	return result
}
