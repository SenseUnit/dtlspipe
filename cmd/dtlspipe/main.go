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

	"github.com/Snawoot/dtlspipe/keystore"
	"github.com/Snawoot/dtlspipe/server"
	"github.com/Snawoot/dtlspipe/util"
)

const (
	ProgName     = "dtlspipe"
	PSKEnvVarKey = "DTLSPIPE_PSK"
)

var (
	version = "undefined"

	timeout   = flag.Duration("timeout", 10*time.Second, "network operation timeout")
	idleTime  = flag.Duration("idle-time", 90*time.Second, "max idle time for UDP session")
	pskHexOpt = flag.String("psk", "", "hex-encoded pre-shared key. Can be generated with genpsk subcommand")
	keyLength = flag.Uint("key-length", 16, "generate key with specified length")
)

func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "%s [OPTION]... server <BIND ADDRESS> <REMOTE ADDRESS>\n", ProgName)
	fmt.Fprintf(out, "%s [OPTION]... client <BIND ADDRESS> <REMOTE ADDRESS>\n", ProgName)
	fmt.Fprintf(out, "%s [OPTION]... genpsk\n", ProgName)
	fmt.Fprintf(out, "%s version\n", ProgName)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Options:")
	flag.PrintDefaults()
}

func cmdGenPSK() int {
	if *keyLength > 64 {
		fmt.Fprintln(os.Stderr, "key length is too big")
		return 1
	}
	psk, err := util.GenPSKHex(int(*keyLength))
	if err != nil {
		fmt.Fprintf(os.Stderr, "key generation error: %v\n", err)
		return 1
	}

	fmt.Println(psk)
	return 0
}

func cmdVersion() int {
	fmt.Println(version)
	return 0
}

func cmdClient(bindAddress, remoteAddress string) int {
	_, err := simpleGetPSK()
	if err != nil {
		log.Printf("can't get PSK: %v", err)
		return 2
	}
	log.Printf("starting dtlspipe client: %s =[wrap into DTLS]=> %s", bindAddress, remoteAddress)
	defer log.Println("dtlspipe client stopped")

	appCtx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	<-appCtx.Done()

	return 0
}

func cmdServer(bindAddress, remoteAddress string) int {
	psk, err := simpleGetPSK()
	if err != nil {
		log.Printf("can't get PSK: %v", err)
		return 2
	}
	log.Printf("starting dtlspipe server: %s =[unwrap from DTLS]=> %s", bindAddress, remoteAddress)
	defer log.Println("dtlspipe server stopped")

	appCtx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cfg := server.Config{
		BindAddress:   bindAddress,
		RemoteAddress: remoteAddress,
		PSKCallback:   keystore.NewStaticKeystore(psk).PSKCallback,
		Timeout:       *timeout,
		IdleTimeout:   *idleTime,
		BaseContext:   appCtx,
	}

	srv, err := server.New(&cfg)
	if err != nil {
		log.Fatalf("server startup failed: %v", err)
	}
	defer srv.Close()

	<-appCtx.Done()
	return 0
}

func run() int {
	flag.CommandLine.Usage = usage
	flag.Parse()
	args := flag.Args()

	switch len(args) {
	case 1:
		switch args[0] {
		case "genpsk":
			return cmdGenPSK()
		case "version":
			return cmdVersion()
		}
	case 3:
		switch args[0] {
		case "server":
			return cmdServer(args[1], args[2])
		case "client":
			return cmdClient(args[1], args[2])
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

func simpleGetPSK() ([]byte, error) {
	pskHex := os.Getenv(PSKEnvVarKey)
	if pskHex == "" {
		os.Unsetenv(PSKEnvVarKey)
	}
	if *pskHexOpt != "" {
		pskHex = *pskHexOpt
	}
	if pskHex == "" {
		return nil, fmt.Errorf("no PSK command line option provided and neither %s environment variable is set", PSKEnvVarKey)
	}
	psk, err := util.PSKFromHex(pskHex)
	if err != nil {
		return nil, fmt.Errorf("can't hex-decode PSK: %w", err)
	}
	return psk, nil
}
