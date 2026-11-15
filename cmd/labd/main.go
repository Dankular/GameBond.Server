//go:build linux

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Dankular/GameBond.Server/lab"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	socket := env("GAMEBOND_LAB_SHAPER_SOCKET", "/run/gamebond-lab/shaper.sock")
	dockerSocket := env("GAMEBOND_LAB_DOCKER_SOCKET", "/var/run/docker.sock")
	netnsDir := env("GAMEBOND_LAB_NETNS_DIR", "/var/run/docker/netns")
	if err := lab.ServeHostShaper(ctx, socket, dockerSocket, netnsDir); err != nil {
		log.Fatal(err)
	}
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
