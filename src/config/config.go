package config

import (
	"os"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Modules []BPFModule `yaml:"modules"`
}

type BPFModule struct {
	Path     string                 `yaml:"path"`
	Mapname  string                 `yaml:"mapname"`
	Programs map[string]AttachInfo `yaml:"programs"`
}

type AttachInfo struct {
	Function string `yaml:"function"`
	Type     string `yaml:"type"`
	Binary   string `yaml:"binary,omitempty"` // uretprobe 등만 필요
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}