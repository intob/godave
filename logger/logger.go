package logger

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
)

type Logger interface {
	Log(level LogLevel, msg string, args ...any)
	WithPrefix(prefix string) Logger
}

type LogLevel int

const (
	ERROR = LogLevel(0)
	DEBUG = LogLevel(1)
)

type DaveLoggerCfg struct {
	Level  LogLevel
	Output chan<- string
	Prefix string
}

type DaveLogger struct {
	level  LogLevel
	output chan<- string
	prefix string
}

func StdOut(buffered bool) chan<- string {
	logs := make(chan string, 100)
	go func() {
		var out io.Writer
		if buffered {
			out = bufio.NewWriter(os.Stdout)
		} else {
			out = os.Stdout
		}
		for l := range logs {
			fmt.Fprintln(out, l)
		}
	}()
	return logs
}

func DevNull() chan<- string {
	logs := make(chan string, 100)
	go func() {
		for range logs {
		}
	}()
	return logs
}

func NewDaveLogger(cfg *DaveLoggerCfg) (*DaveLogger, error) {
	if cfg == nil {
		return nil, errors.New("cfg is nil")
	}
	if cfg.Output == nil {
		return nil, errors.New("logger output is nil")
	}
	return &DaveLogger{
		level:  cfg.Level,
		output: cfg.Output,
		prefix: cfg.Prefix,
	}, nil
}

func NewDaveLoggerToDevNull() *DaveLogger {
	return &DaveLogger{
		output: DevNull(),
	}
}

func (l *DaveLogger) Log(level LogLevel, msg string, args ...any) {
	if level > l.level {
		return
	}
	l.output <- fmt.Sprintf(l.prefix+" "+msg, args...)
}

func (l *DaveLogger) Error(msg string, args ...any) {
	l.Log(ERROR, msg, args...)
}

func (l *DaveLogger) Debug(msg string, args ...any) {
	l.Log(DEBUG, msg, args...)
}

func (l *DaveLogger) WithPrefix(prefix string) Logger {
	return &DaveLogger{
		level:  l.level,
		output: l.output,
		prefix: l.prefix + prefix,
	}
}

func (l *DaveLogger) Level() LogLevel {
	return l.level
}
