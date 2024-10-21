package farcasterd

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Logger initialization.
func initLogger(debug bool, path string) *zap.SugaredLogger {
	var level zap.AtomicLevel

	if debug {
		level = zap.NewAtomicLevelAt(zap.DebugLevel)
	} else {
		level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	enc := zapcore.NewConsoleEncoder(zapcore.EncoderConfig{
		MessageKey:   "message",
		LevelKey:     "level",
		TimeKey:      "time",
		NameKey:      "name",
		CallerKey:    "caller",
		EncodeTime:   zapcore.RFC3339TimeEncoder,
		EncodeLevel:  zapcore.CapitalLevelEncoder,
		EncodeCaller: zapcore.ShortCallerEncoder,
	})

	// Log to file if specified; send logs to stderr otherwise.
	// Use lumberjack to rotate logs.
	var w zapcore.WriteSyncer
	if path != "" {
		w = zapcore.AddSync(&lumberjack.Logger{
			Filename:   path,
			MaxSize:    1, // megabytes
			MaxBackups: 1,
			MaxAge:     60, // days
		})
	} else {
		// stderr must be locked to avoid interleaving logs.
		w = zapcore.Lock(os.Stderr)
	}

	core := zapcore.NewCore(enc, w, level)
	logger := zap.New(core)

	return logger.Sugar()
}
