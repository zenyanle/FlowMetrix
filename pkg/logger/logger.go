package logger

import (
	"os"

	"github.com/sirupsen/logrus"
)

// 初始化 logrus 配置
func init() {
	logrus.SetOutput(os.Stdout) // 设置日志输出到标准输出

	// 使用 TextFormatter（默认文本格式）
	logrus.SetFormatter(&logrus.TextFormatter{
		ForceColors:     true,                  // 强制启用颜色
		FullTimestamp:   true,                  // 显示完整时间戳
		TimestampFormat: "2006-01-02 15:04:05", // 自定义时间格式
	})

	logrus.SetLevel(logrus.InfoLevel) // 设置默认日志级别为 Info
}

// SetLevel 设置日志级别
func SetLevel(level logrus.Level) {
	logrus.SetLevel(level)
}

// WithFields 添加字段到日志
func WithFields(fields map[string]interface{}) *logrus.Entry {
	return logrus.WithFields(fields)
}

// Debug 记录 Debug 级别的日志
func Debug(args ...interface{}) {
	logrus.Debug(args...)
}

// Debugf 记录 Debug 级别的格式化日志
func Debugf(format string, args ...interface{}) {
	logrus.Debugf(format, args...)
}

// Info 记录 Info 级别的日志
func Print(args ...interface{}) {
	logrus.Info(args...)
}

// Infof 记录 Info 级别的格式化日志
func Printf(format string, args ...interface{}) {
	logrus.Infof(format, args...)
}

// Warn 记录 Warn 级别的日志
func Warn(args ...interface{}) {
	logrus.Warn(args...)
}

// Warnf 记录 Warn 级别的格式化日志
func Warnf(format string, args ...interface{}) {
	logrus.Warnf(format, args...)
}

// Error 记录 Error 级别的日志
func Error(args ...interface{}) {
	logrus.Error(args...)
}

// Errorf 记录 Error 级别的格式化日志
func Errorf(format string, args ...interface{}) {
	logrus.Errorf(format, args...)
}

// Fatal 记录 Fatal 级别的日志
func Fatal(args ...interface{}) {
	logrus.Fatal(args...)
}

// Fatalf 记录 Fatal 级别的格式化日志
func Fatalf(format string, args ...interface{}) {
	logrus.Fatalf(format, args...)
}

// Panic 记录 Panic 级别的日志
func Panic(args ...interface{}) {
	logrus.Panic(args...)
}

// Panicf 记录 Panic 级别的格式化日志
func Panicf(format string, args ...interface{}) {
	logrus.Panicf(format, args...)
}
