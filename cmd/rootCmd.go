package cmd

import (
	"context"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"os"
	"os/signal"
	"scan/scan"
	"strconv"
	"strings"
	"syscall"
	"time"
)

//默认值
var debug bool                //日志级别
var timeoutMS int = 1000      //连接超时
var parallelism int = 500     //并发数量
var portSelection string      //指定端口
var scanType = "connect"      //扫描模式
var hideUnavailableHosts bool //省略无效的host
var versionRequested bool     //打印版本

//初始话命令

func init() {
	//带P的表示同时可接收缩写选项,P代表可以设置短指令
	rootCmd.PersistentFlags().BoolVarP(&hideUnavailableHosts, "up-only", "u", hideUnavailableHosts, "Omit output for hosts which are not up")
	rootCmd.PersistentFlags().BoolVarP(&versionRequested, "version", "", versionRequested, "Output version information and exit")
	rootCmd.PersistentFlags().StringVarP(&scanType, "scan-type", "s", scanType, "Scan type. Must be one of stealth, connect")
	rootCmd.PersistentFlags().BoolVarP(&debug, "verbose", "v", debug, "Enable verbose logging")
	rootCmd.PersistentFlags().IntVarP(&timeoutMS, "timeout-ms", "t", timeoutMS, "Scan timeout in MS")
	rootCmd.PersistentFlags().IntVarP(&parallelism, "workers", "w", parallelism, "Parallel routines to scan on")
	rootCmd.PersistentFlags().StringVarP(&portSelection, "ports", "p", portSelection, "Port to scan. Comma separated, can sue hyphens e.g. 22,80,443,8080-8090")
}

func createScanner(ti *scan.TargetIterator, scanType string,
	timeout time.Duration, routines int) (scan.Scanner, error) {
	//根据scanType来选择扫描模式
	switch strings.ToLower(scanType) {
	case "stealth", "syn", "fast": //SYN扫描
		if os.Geteuid() > 0 { //用于判断是否是root用户
			return nil, fmt.Errorf("permission denied")
		}

	case "connect": //TCP连接扫描
		return scan.NewConnectScanner(ti, timeout, routines), nil

	case "device": //设备扫描

	}
	return nil, fmt.Errorf("未知扫描模式:%v", scanType)
}

var rootCmd = &cobra.Command{
	Use:   "scanner",
	Short: "high performance scanner!",
	Run: func(cmd *cobra.Command, args []string) { //主要的执行函数
		if versionRequested {
			fmt.Println("development version")
			os.Exit(1)
		}
		if debug {
			log.SetLevel(log.DebugLevel) //设置日志级别
		}
		//检查是否输入ip
		if len(args) == 0 {
			fmt.Println("至少指定一个目标IP!")
			os.Exit(1)
		}

		//检查端口flag的输入,没有指定的话用默认的端口,返回[]int
		ports, err := getPorts(portSelection)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		//设置一个主动取消的机制
		ctx, cancel := context.WithCancel(context.Background())
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-c //阻塞直到有信号
			fmt.Println("退出...")
			cancel()
		}()

		start := time.Now()
		fmt.Printf("\n开始扫描[%s]\n\n", start)

		//开始解析输入的IP(这里IP是作为os.Args,而不是flag
		for _, target := range args {
			//对输入的参数进行解析,构建迭代器(如果是CIDR则会含有ipnet等字段)
			targetinterator := scan.NewTargetInteractor(target)
			//对迭代器创建扫描器
			scanner, err := createScanner(targetinterator, scanType, time.Duration(timeoutMS), parallelism)
			if err != nil {
				log.Fatal(err)
			}

			log.Debugf("开始扫描...")
			if err := scanner.Start(); err != nil {
				log.Fatal(err)
			}
			log.Debugf("开始扫描:%v", target)

			//生产者,并汇总结果
			results, err := scanner.Scan(ctx, ports)
			if err != nil {
				log.Fatal(err)
			}

			//将结果打印
			for _, result := range results {
				if !hideUnavailableHosts || result.IsHostUp() {
					scanner.OutPutReault(result)
				}

			}

		}
		fmt.Printf("扫描完毕 耗时:%v\n", time.Since(start).String())
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func getPorts(selection string) ([]int, error) {
	if selection == "" {
		//TODO:使用内置的端口
		return nil, errors.New("请指定端口!")
	}

	ports := []int{}
	ranges := strings.Split(selection, ",")
	for _, r := range ranges {
		r = strings.TrimSpace(r)
		if strings.Contains(r, "-") { //分别解析起始结束端口
			parts := strings.Split(r, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("Invalid port selection segment: '%s'", r)
			}

			p1, err := strconv.Atoi(parts[0])
			if err != nil {
				return nil, fmt.Errorf("Invalid port number: '%s'", parts[0])
			}

			p2, err := strconv.Atoi(parts[1])
			if err != nil {
				return nil, fmt.Errorf("Invalid port number: '%s'", parts[1])
			}

			if p1 > p2 {
				return nil, fmt.Errorf("Invalid port range: %d-%d", p1, p2)
			}

			for i := p1; i <= p2; i++ {
				ports = append(ports, i)
			}

		} else { //按单个情况处理
			if port, err := strconv.Atoi(r); err != nil {
				return nil, fmt.Errorf("Invalid port number: '%s'", r)
			} else {
				if port > 65535 || port < 1 {
					return nil, fmt.Errorf("Invalid port number:%s,port number must be between 1 and 65535", r)
				}
				ports = append(ports, port)
			}
		}
	}
	return ports, nil

}
