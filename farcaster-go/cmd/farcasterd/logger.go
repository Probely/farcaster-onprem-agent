package farcasterd

import (
	"fmt"
	"os"
	"path/filepath"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
	"probely.com/farcaster/osutils"
)

// Logger initialization.
func initLogger(debug bool, path string) (*zap.SugaredLogger, error) {
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
		// Create the directory if it doesn't exist.
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create directory for log file: %v", err)
		}

		// Set platform-specific permissions if needed
		if err := osutils.LockDownPermissions(dir); err != nil {
			return nil, fmt.Errorf("failed to set directory permissions: %v", err)
		}

		w = zapcore.AddSync(&lumberjack.Logger{
			Filename:   path,
			MaxSize:    1, // MB
			MaxBackups: 1,
			MaxAge:     60, // days
		})
	} else {
		// stderr must be locked to avoid interleaving logs.
		w = zapcore.Lock(os.Stderr)
	}

	core := zapcore.NewCore(enc, w, level)
	logger := zap.New(core)

	return logger.Sugar(), nil
}
