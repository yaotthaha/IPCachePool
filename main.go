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
	"sync"
	"syscall"
)

var (
	AppName    = "IPCachePool"
	AppAuthor  = "Yaott"
	AppVersion = "v0.0.1-build-2"
)

var (
	Ctx     context.Context
	CtxFunc context.CancelFunc
	RunLock = &sync.Mutex{}
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
	flag.StringVar(&ParamMode, "mode", "", "Mode: server or client")
	flag.StringVar(&ParamConfigFile, "config", "./config.json", "Config file")
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
		_, _ = fmt.Fprintln(os.Stdout, fmt.Sprintf("Private Key: ==>\n%s\n<==\n Public Key: ==>\n%s\n<==\n", PriKey, PubKey))
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
	Log.Println(fmt.Sprintf("run mode: %s", coreType))
	Log.Println(fmt.Sprintf("read config file: %s", filename))
	switch coreType {
	case "server":
		cfg, err := server.Parse(filename)
		if err != nil {
			Log.Println(fmt.Sprintf("read config file error: %s", err))
			return
		}
		go SetupCloseHandler()
		Ctx, CtxFunc = context.WithCancel(context.Background())
		RunLock.Lock()
		cfg.ServerRun(Ctx)
		RunLock.Unlock()
	case "client":
		cfg, err := client.Parse(filename)
		if err != nil {
			Log.Println(fmt.Sprintf("read config file error: %s", err))
			return
		}
		go SetupCloseHandler()
		Ctx, CtxFunc = context.WithCancel(context.Background())
		RunLock.Lock()
		cfg.ClientRun(Ctx)
		RunLock.Unlock()
	}
	Log.Println("Bye!!!")
}

func SetupCloseHandler() {
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		if RunLock != nil {
			RunLock.Lock()
			CtxFunc()
			RunLock.Unlock()
			os.Exit(0)
		}
		os.Exit(0)
	}()
}
