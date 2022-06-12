package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/yaotthaha/IPCachePool/client"
	easyclient "github.com/yaotthaha/IPCachePool/easy-client"
	"github.com/yaotthaha/IPCachePool/logplus"
	"github.com/yaotthaha/IPCachePool/server"
	"github.com/yaotthaha/IPCachePool/tool"
	"os"
	"os/signal"
	"syscall"
)

var (
	AppName    = "IPCachePool"
	AppAuthor  = "Yaott"
	AppVersion = "v0.2.0-build-4"
)

var (
	Log     *logplus.LogPlus
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
	flag.StringVar(&ParamMode, "m", "", "Mode: server or client or easy-client")
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
	case "easy-client", "Easy-client", "EASY-CLIENT", "e", "E":
		if ParamConfigFile == "" {
			_, _ = fmt.Fprintln(os.Stdout, "Config file is required")
			return
		}
		CoreRun(ParamConfigFile, "easy-client")
	default:
		_, _ = fmt.Fprintln(os.Stdout, "Mode is required")
		return
	}
}

func CoreRun(filename string, coreType string) {
	Log = logplus.NewLogPlus(logplus.LogPlusOption{Lfile: 1, Debug: false})
	Log.Println(logplus.Info, fmt.Sprintf("%s %s (Build From %s)", AppName, AppVersion, AppAuthor))
	Log.Println(logplus.Info, fmt.Sprintf("run mode: %s", coreType))
	Log.Println(logplus.Info, fmt.Sprintf("read config file: %s", filename))
	switch coreType {
	case "server":
		cfg, err := server.Parse(filename)
		if err != nil {
			Log.Println(logplus.Error, fmt.Sprintf("read config file error: %s", err))
			return
		}
		Log.Println(logplus.Info, "read config file success")
		go SetupCloseHandler()
		Ctx, CtxFunc = context.WithCancel(context.Background())
		Log.Println(logplus.Info, "server running")
		cfg.ServerRun(Ctx, Log)
	case "client":
		cfg, err := client.Parse(filename)
		if err != nil {
			Log.Println(logplus.Error, fmt.Sprintf("read config file error: %s", err))
			return
		}
		Log.Println(logplus.Info, "read config file success")
		go SetupCloseHandler()
		Ctx, CtxFunc = context.WithCancel(context.Background())
		Log.Println(logplus.Info, "client running")
		cfg.ClientRun(Ctx, Log)
	case "easy-client":
		cfg, err := easyclient.Parse(filename)
		if err != nil {
			Log.Println(logplus.Error, fmt.Sprintf("read config file error: %s", err))
			return
		}
		Log.Println(logplus.Info, "read config file success")
		cfg.EasyClientRun(Log)
	}
	Log.Println(logplus.Info, "Bye!!!")
}

func SetupCloseHandler() {
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM|syscall.SIGKILL)
	go func() {
		<-c
		Log.Println(logplus.Warning, "Interrupt signal received, shutting down...")
		CtxFunc()
	}()
}
