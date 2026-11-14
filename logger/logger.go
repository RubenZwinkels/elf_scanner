package logger

import (
	"fmt"
	"io"
	"strings"
)

// Level controls which log messages are written.
type Level uint8

const (
	InfoLevel Level = iota
	WarningLevel
	CriticalLevel
)

// ParseLevel converts a command-line value into a log level.
func ParseLevel(value string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "info":
		return InfoLevel, nil
	case "warning", "warn":
		return WarningLevel, nil
	case "critical", "crit":
		return CriticalLevel, nil
	default:
		return InfoLevel, fmt.Errorf("unsupported log level %q (expected info, warning, or critical)", value)
	}
}

// Logger writes messages at or above its configured minimum level.
type Logger struct {
	output io.Writer
	level  Level
}

func New(output io.Writer, level Level) *Logger {
	return &Logger{output: output, level: level}
}

func (l *Logger) Info(format string, args ...any) {
	l.log(InfoLevel, "INFO", format, args...)
}

func (l *Logger) Warning(format string, args ...any) {
	l.log(WarningLevel, "WARNING", format, args...)
}

func (l *Logger) Critical(format string, args ...any) {
	l.log(CriticalLevel, "CRITICAL", format, args...)
}

func (l *Logger) Print(args ...any) {
	l.print(fmt.Sprint(args...))
}

func (l *Logger) Printf(format string, args ...any) {
	l.print(fmt.Sprintf(format, args...))
}

func (l *Logger) Println(args ...any) {
	l.print(fmt.Sprintln(args...))
}

func (l *Logger) log(level Level, label string, format string, args ...any) {
	if level < l.level {
		return
	}

	_, _ = fmt.Fprintf(l.output, "[%s] %s\n", label, fmt.Sprintf(format, args...))
}

func (l *Logger) print(message string) {
	if InfoLevel < l.level {
		return
	}

	_, _ = fmt.Fprint(l.output, message)
}
