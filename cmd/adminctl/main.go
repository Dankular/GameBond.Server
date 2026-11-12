// Command adminctl prepares the admin portal's credentials: a password hash
// for the server config and a self-signed TLS certificate (admin/cli.py).
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Dankular/GameBond.Server/adminauth"
	"github.com/Dankular/GameBond.Server/adminportal"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: adminctl passwd | adminctl cert DIR [-host NAME,...] [-days N]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "passwd":
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		h, err := adminauth.HashPassword(strings.TrimRight(line, "\r\n"), 32768)
		if err != nil {
			fmt.Fprintln(os.Stderr, "adminctl:", err)
			os.Exit(1)
		}
		fmt.Println(h)
	case "cert":
		fs := flag.NewFlagSet("cert", flag.ExitOnError)
		hosts := fs.String("host", "localhost,127.0.0.1", "comma separated names/IPs")
		days := fs.Int("days", 825, "validity")
		dir := ""
		args := os.Args[2:]
		if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
			dir, args = args[0], args[1:]
		}
		_ = fs.Parse(args)
		if dir == "" {
			fmt.Fprintln(os.Stderr, "adminctl: cert needs DIR")
			os.Exit(2)
		}
		res, err := adminportal.WriteSelfSigned(dir, strings.Split(*hosts, ","), *days)
		if err != nil {
			fmt.Fprintln(os.Stderr, "adminctl:", err)
			os.Exit(1)
		}
		_ = json.NewEncoder(os.Stdout).Encode(res)
	default:
		fmt.Fprintln(os.Stderr, "adminctl: unknown command", os.Args[1])
		os.Exit(2)
	}
}
