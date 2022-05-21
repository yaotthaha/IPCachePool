package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/yaotthaha/IPCachePool/client"
	"github.com/yaotthaha/IPCachePool/server"
	"github.com/yaotthaha/IPCachePool/tool"
	"log"
	"os"
	"os/signal"
	"syscall"
)

var (
	AppName    = "IPCachePool"
	AppAuthor  = "Yaott"
	AppVersion = "v0.1.1-build-1"
)

var (
	Ctx     context.Context
	CtxFunc context.CancelFunc
)

var (
	ParamMode       string
	ParamHelp       bool
	ParamVersion    bool
	ParamConfigFile string
	ParamGenKey     bool
)

func main() {
	flag.BoolVar(&ParamHelp, "h", false, "Show help")
	flag.BoolVar(&ParamVersion, "v", false, "Show version")
	flag.StringVar(&ParamMode, "m", "", "Mode: server or client")
	flag.StringVar(&ParamConfigFile, "c", "./config.json", "Config file")
	flag.BoolVar(&ParamGenKey, "genkey", false, "Generate key")
	flag.Parse()
	if ParamVersion {
		_, _ = fmt.Fprintln(os.Stdout, fmt.Sprintf("%s %s (Build From %s)", AppName, AppVersion, AppAuthor))
		return
	}
	if ParamHelp {
		_, _ = fmt.Fprintln(os.Stdout, fmt.Sprintf("%s %s (Build From %s)", AppName, AppVersion, AppAuthor))
		flag.Usage()
		return
	}
	if ParamGenKey {
		PriKey, PubKey, err := tool.ECCKeyGen()
		if err != nil {
			_, _ = fmt.Fprintln(os.Stdout, fmt.Sprintf("ECC key generate error: %s", err))
			return
		}
		_, _ = fmt.Fprintln(os.Stdout, fmt.Sprintf("Private Key: \n==>\n%s\n<==\n\nPublic Key: \n==>\n%s\n<==\n", PriKey, PubKey))
		return
	}
	if ParamMode == "" {
		_, _ = fmt.Fprintln(os.Stdout, fmt.Sprintf("%s %s (Build From %s)", AppName, AppVersion, AppAuthor))
		flag.Usage()
		return
	}
	switch ParamMode {
	case "server", "Server", "SERVER", "s", "S":
		if ParamConfigFile == "" {
			_, _ = fmt.Fprintln(os.Stdout, "Config file is required")
			return
		}
		CoreRun(ParamConfigFile, "server")
	case "client", "Client", "CLIENT", "c", "C":
		if ParamConfigFile == "" {
			_, _ = fmt.Fprintln(os.Stdout, "Config file is required")
			return
		}
		CoreRun(ParamConfigFile, "client")
	default:
		_, _ = fmt.Fprintln(os.Stdout, "Mode is required")
		return
	}
}

func CoreRun(filename string, coreType string) {
	Log := log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lshortfile)
	Log.Println(fmt.Sprintf("%s %s (Build From %s)", AppName, AppVersion, AppAuthor))
	Log.Println(fmt.Sprintf("run mode: %s", coreType))
	Log.Println(fmt.Sprintf("read config file: %s", filename))
	switch coreType {
	case "server":
		cfg, err := server.Parse(filename)
		if err != nil {
			Log.Println(fmt.Sprintf("read config file error: %s", err))
			return
		}
		Log.Println("read config file success")
		go SetupCloseHandler()
		Ctx, CtxFunc = context.WithCancel(context.Background())
		Log.Println("server running")
		cfg.ServerRun(Ctx)
	case "client":
		cfg, err := client.Parse(filename)
		if err != nil {
			Log.Println(fmt.Sprintf("read config file error: %s", err))
			return
		}
		Log.Println("read config file success")
		go SetupCloseHandler()
		Ctx, CtxFunc = context.WithCancel(context.Background())
		Log.Println("client running")
		cfg.ClientRun(Ctx)
	}
	Log.Println("Bye!!!")
}

func SetupCloseHandler() {
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM|syscall.SIGKILL)
	go func() {
		<-c
		_, _ = fmt.Fprintln(os.Stdout, "interrupted by system")
		CtxFunc()
	}()
}
