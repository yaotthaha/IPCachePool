package logplus

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

var version = "v0.0.3"

type LogPlus struct {
	Log     *log.Logger
	LogFile *os.File
	Option  LogPlusOption
}

type LogPlusOption struct {
	Lfile int // 0: off 1: shortfile 2: longfile
	Debug bool
}

type LogLevel int

const (
	debug   = "Debug"
	warning = "Warning"
	err     = "Error"
	fatal   = "Fatal"
	info    = "Info"
	unknown = "Unknown"
)

const (
	Debug   LogLevel = 2
	Warning LogLevel = 1
	Error   LogLevel = -1
	Fatal   LogLevel = -2
	Info    LogLevel = 0
)

func (l LogLevel) transLevel() string {
	switch l {
	case Debug:
		return debug
	case Warning:
		return warning
	case Error:
		return err
	case Fatal:
		return fatal
	case Info:
		return info
	default:
		return unknown
	}
}

func (l *LogPlus) Stop() {
	if l.LogFile != nil {
		_ = l.LogFile.Close()
	}
}

func NewLogPlusWithLogFile(filename string, option LogPlusOption) (*LogPlus, error) {
	var l *LogPlus
	if filename != "" {
		file, Err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0777)
		if Err != nil {
			return nil, errors.New(fmt.Sprintf("open log file fail: %s", err))
		}
		l = &LogPlus{
			Log:     log.New(file, "", 0),
			LogFile: file,
			Option:  option,
		}
		return l, nil
	} else {
		return nil, errors.New("log file name is empty")
	}
}

func NewLogPlus(option LogPlusOption) *LogPlus {
	return &LogPlus{
		Log:     log.New(os.Stdout, "", 0),
		LogFile: nil,
		Option:  option,
	}
}

func (l *LogPlus) SetOutputToFile(filename string) error {
	if filename != "" {
		file, Err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0777)
		if Err != nil {
			return errors.New(fmt.Sprintf("open log file fail: %s", err))
		}
		l.LogFile = file
		l.Log.SetOutput(file)
		return nil
	} else {
		return errors.New("log file name is empty")
	}
}

func (l *LogPlus) SetOutput(output io.Writer) {
	l.Log.SetOutput(output)
	if l.LogFile != nil {
		l.LogFile = nil
		_ = l.LogFile.Close()
	}
}

func timeNow() string {
	return time.Now().Format("2006-01-02 15:04:05 MST")
}

func (l *LogPlus) do(loglevel LogLevel, format string, v ...interface{}) string {
	op := fmt.Sprintf("[%s] [%s] ", timeNow(), loglevel.transLevel())
	switch l.Option.Lfile {
	case 0:
	case 1:
		_, file, line, ok := runtime.Caller(3)
		if ok {
			op += fmt.Sprintf("{%s:%d} ", filepath.Base(file), line)
		}
	case 2:
		_, file, line, ok := runtime.Caller(3)
		if ok {
			op += fmt.Sprintf("{%s:%d} ", file, line)
		}
	default:
	}
	op += fmt.Sprintf(format, v...)
	return op
}

func (l *LogPlus) Printf(loglevel LogLevel, format string, v ...interface{}) {
	if !l.Option.Debug && loglevel == Debug {
		return
	}
	l.Log.Print(l.do(loglevel, format, v...))
}

func (l *LogPlus) Println(loglevel LogLevel, v interface{}) {
	if !l.Option.Debug && loglevel == Debug {
		return
	}
	l.Printf(loglevel, "%s\n", v)
}

func (l *LogPlus) Fatalf(loglevel LogLevel, format string, v ...interface{}) {
	if !l.Option.Debug && loglevel == Debug {
		return
	}
	l.Log.Fatalf(l.do(loglevel, format, v...))
}

func (l *LogPlus) Fatalln(loglevel LogLevel, v interface{}) {
	if !l.Option.Debug && loglevel == Debug {
		return
	}
	l.Fatalf(loglevel, "%s\n", v)
}

func (l *LogPlus) Panicf(loglevel LogLevel, format string, v ...interface{}) {
	if !l.Option.Debug && loglevel == Debug {
		return
	}
	l.Log.Panicf(l.do(loglevel, format, v...))
}

func (l *LogPlus) Panicln(loglevel LogLevel, v interface{}) {
	if !l.Option.Debug && loglevel == Debug {
		return
	}
	l.Panicf(loglevel, "%s\n", v)
}
