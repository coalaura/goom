package main

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/goccy/go-yaml"
)

//go:embed default.yml
var defaultConfig []byte

type Config struct {
	Exclude []string `yaml:"exclude"`
}

type excludeSnapshot struct {
	patterns [][]byte
}

var (
	configMu sync.Mutex

	loadedConfigPath    string
	loadedConfigModTime int64
	loadedConfigSize    int64

	excludedPatterns atomic.Pointer[excludeSnapshot]
)

func loadConfig(homeDir string) {
	if homeDir == "" {
		return
	}

	configMu.Lock()
	defer configMu.Unlock()

	configPath := filepath.Join(homeDir, "goom.yml")

	info, err := os.Stat(configPath)
	if os.IsNotExist(err) {
		sendMsg(0, "Configuration file not found. Pre-filling default goom.yml...")

		err = os.WriteFile(configPath, []byte(defaultConfig), 0644)
		if err != nil {
			sendMsg(1, fmt.Sprintf("Failed to write default config: %v", err.Error()))

			return
		}

		info, err = os.Stat(configPath)
	}

	if err != nil {
		sendMsg(1, fmt.Sprintf("Failed to check config file: %v", err.Error()))

		return
	}

	modTime := info.ModTime().UnixNano()
	size := info.Size()

	if configPath == loadedConfigPath && modTime == loadedConfigModTime && size == loadedConfigSize {
		return
	}

	sendMsg(0, fmt.Sprintf("Loading configuration: %s", configPath))

	file, err := os.OpenFile(configPath, os.O_RDONLY, 0)
	if err != nil {
		sendMsg(1, fmt.Sprintf("Failed to read config file: %v", err.Error()))

		return
	}

	defer file.Close()

	var cfg Config

	err = yaml.NewDecoder(file).Decode(&cfg)
	if err != nil {
		sendMsg(1, fmt.Sprintf("Failed to decode config: %v", err.Error()))

		return
	}

	patterns := make([][]byte, 0, len(cfg.Exclude))

	for _, pattern := range cfg.Exclude {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}

		patterns = append(patterns, []byte(pattern))
	}

	excludedPatterns.Store(&excludeSnapshot{patterns: patterns})

	loadedConfigPath = configPath
	loadedConfigModTime = modTime
	loadedConfigSize = size

	sendMsg(0, fmt.Sprintf("Loaded %d excluded process pattern(s)", len(patterns)))
}

func isExcluded(name []byte) bool {
	snapshot := excludedPatterns.Load()
	if snapshot == nil {
		return false
	}

	return ContainsAnyFold(name, snapshot.patterns)
}
