// Command adminportal-probe serves the Go admin portal over plain HTTP with a
// fixed snapshot so tools/compare_admin_portals.py can drive it and the Python
// portal with identical requests.
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"

	"github.com/Dankular/GameBond.Server/adminportal"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: adminportal-probe CONFIG HASH")
		os.Exit(2)
	}
	raw, _ := json.Marshal(map[string]any{"enabled": true, "bind": []any{"127.0.0.1", freePort()}, "password_hash": os.Args[2]})
	s, err := adminportal.ParseSettings(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	p := adminportal.New(adminportal.Options{Settings: s, ConfigPath: os.Args[1], Snapshot: func() any { return map[string]any{"version": "x", "pid": 1} }})
	if err := p.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(p.Port)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
}

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
