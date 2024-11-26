package logger

import "fmt"

type LogLevel int

const (
	ERROR = LogLevel(0)
	DEBUG = LogLevel(1)
)

type LoggerCfg struct {
	Level  LogLevel
	Output chan<- string
	Prefix string
}

type Logger struct {
	level  LogLevel
	output chan<- string
	prefix string
}

func NewLogger(cfg *LoggerCfg) *Logger {
	return &Logger{
		level:  cfg.Level,
		output: cfg.Output,
		prefix: cfg.Prefix + " ",
	}
}

func (l *Logger) Log(level LogLevel, msg string, args ...any) {
	if level > l.level {
		return
	}
	select {
	case l.output <- fmt.Sprintf(l.prefix+msg, args...):
	default:
	}

}

func (l *Logger) Error(msg string, args ...any) {
	l.Log(ERROR, msg, args...)
}

func (l *Logger) Debug(msg string, args ...any) {
	l.Log(DEBUG, msg, args...)
}

func (l *Logger) WithPrefix(prefix string) *Logger {
	return &Logger{
		level:  l.level,
		output: l.output,
		prefix: prefix + " ",
	}
}

func (l *Logger) Level() LogLevel {
	return l.level
}
