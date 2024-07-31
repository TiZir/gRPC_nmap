package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/TiZir/gRPC_nmap/internal/config"
	"github.com/TiZir/gRPC_nmap/internal/grpcapp"
	"github.com/TiZir/gRPC_nmap/internal/logger"
)

func main() {
	//configure
	cfg := config.MustLoad()
	//log
	log := logger.SetupLogger(cfg.Level)
	//app with service
	log.Info("starting gRPC server")
	app := grpcapp.New(log, cfg.GRPC.Port, "vulners")
	go app.MustRun()
	//shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	<-stop
	app.Stop()
	log.Info("application stopped")
}
