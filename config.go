package main

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"
)

//go:embed default.yml
var defaultConfig []byte

type Config struct {
	Exclude []string `yaml:"exclude"`
}

var excludedPatterns [][]byte

func loadConfig(homeDir string) {
	if homeDir == "" {
		return
	}

	configPath := filepath.Join(homeDir, "goom.yml")

	sendMsg(0, fmt.Sprintf("Loading configuration: %s", configPath))

	_, err := os.Stat(configPath)
	if os.IsNotExist(err) {
		sendMsg(0, "Configuration file not found. Pre-filling default goom.yml...")

		err = os.WriteFile(configPath, []byte(defaultConfig), 0644)
		if err != nil {
			sendMsg(1, fmt.Sprintf("Failed to write default config: %v", err.Error()))

			return
		}
	} else if err != nil {
		sendMsg(1, fmt.Sprintf("Failed to check config file: %v", err.Error()))

		return
	}

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

	excludedPatterns = make([][]byte, len(cfg.Exclude))

	for i, pattern := range cfg.Exclude {
		excludedPatterns[i] = []byte(pattern)
	}

	sendMsg(0, fmt.Sprintf("Loaded %d excluded process pattern(s)", len(excludedPatterns)))
}

func isExcluded(name []byte) bool {
	return ContainsAnyFold(name, excludedPatterns)
}
