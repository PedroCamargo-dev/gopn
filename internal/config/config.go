package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type Profile struct {
	Name     string `json:"name"`
	OvpnPath string `json:"ovpn_path"`
	Username string `json:"username"`
}

type Config struct {
	Profiles map[string]Profile `json:"profiles"`
}

var configPath string

func init() {
	home, err := os.UserHomeDir()
	if err != nil {
		panic("Não foi possível obter HOME do usuário")
	}
	configPath = filepath.Join(home, ".config", "gopn", "profiles.json")
}

func Load() (*Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Config{Profiles: make(map[string]Profile)}, nil
		}
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if c.Profiles == nil {
		c.Profiles = make(map[string]Profile)
	}
	return &c, nil
}

func (c *Config) Save() error {
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, data, 0640)
}
