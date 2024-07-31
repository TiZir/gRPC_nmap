package config

import (
	"flag"
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Level string `yaml:"log_level" log_level-default:"info"`
	GRPC  GRPCConfig
}

type GRPCConfig struct {
	// Host    string        `yaml:"host"`
	Port    int           `yaml:"port"`
	Timeout time.Duration `yaml:"timeout"`
}

func MustLoad() *Config {

	// path := fetchConfigPath()
	// if path == "" {
	// 	panic("config path is empty")
	// }
	path := "/home/tikhonov/go/grpc/gRPC_nmap/config/local_cfg.yaml"
	return MustLoadByPath(path)
}

func MustLoadByPath(configPath string) *Config {

	// Проверяем есть ли что-то по пути
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		panic("config file does not exist: " + configPath)
	}

	var cfg Config
	if err := cleanenv.ReadConfig(configPath, &cfg); err != nil {
		panic("failed to read config: " + err.Error())
	}

	return &cfg
}

/*
Позволяет запускать 2 способами
1) CONFIG_PATH = ./path/to/config/config.yaml app
2) app --config=./path...
*/
func fetchConfigPath() string {
	var res string

	//config = "path/to/config.yaml"
	flag.StringVar(&res, "config", "", "path to config file")
	flag.Parse()

	if res == "" {
		res = os.Getenv("CONFIG_PATH")
	}

	return res
}
