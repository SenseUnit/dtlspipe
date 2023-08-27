package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const (
	ProgName = "dtlspipe"
)

var (
	version = "undefined"

	timeout   = flag.Duration("timeout", 10*time.Second, "network operation timeout")
	idleTime  = flag.Duration("idle-time", 90*time.Second, "max idle time for UDP session")
	passwdOpt = flag.String("password", "", "password used to derive PSK key")
)

func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "%s [OPTION]... server <BIND ADDRESS> <REMOTE ADDRESS>\n", ProgName)
	fmt.Fprintf(out, "%s [OPTION]... client <BIND ADDRESS> <REMOTE ADDRESS>\n", ProgName)
	fmt.Fprintf(out, "%s version\n", ProgName)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Options:")
	flag.PrintDefaults()
}

func cmdVersion() int {
	fmt.Println(version)
	return 0
}

func cmdClient(bindAddress, remoteAddress, password string) int {
	log.Printf("starting dtlspipe client: %s => %s", bindAddress, remoteAddress)
	defer log.Println("dtlspipe client stopped")

	appCtx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	<-appCtx.Done()

	return 0
}

func cmdServer(bindAddress, remoteAddress, password string) int {
	log.Printf("starting dtlspipe server: %s => %s", bindAddress, remoteAddress)
	defer log.Println("dtlspipe server stopped")

	appCtx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	<-appCtx.Done()
	return 0
}

func run() int {
	flag.CommandLine.Usage = usage
	flag.Parse()
	args := flag.Args()

	passwd := os.Getenv("PSK_PASSWD")
	if passwd == "" {
		os.Unsetenv("PSK_PASSWD")
	}
	if *passwdOpt != "" {
		passwd = *passwdOpt
	}
	if passwd == "" {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Error: no password option provided and neither PSK_PASSWD environment variable is set")
		fmt.Fprintln(os.Stderr)
		return 2
	}

	switch len(args) {
	case 1:
		switch args[0] {
		case "version":
			return cmdVersion()
		}
	case 3:
		switch args[0] {
		case "server":
			return cmdServer(args[1], args[2], passwd)
		case "client":
			return cmdServer(args[1], args[2], passwd)
		}
	}
	usage()
	return 2
}

func main() {
	log.Default().SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	log.Default().SetPrefix(strings.ToUpper(ProgName) + ": ")
	os.Exit(run())
}
