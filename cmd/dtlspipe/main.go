package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"runtime/pprof"
	"strings"
	"syscall"
	"time"

	"github.com/SenseUnit/dtlspipe/addrgen"
	"github.com/SenseUnit/dtlspipe/ciphers"
	"github.com/SenseUnit/dtlspipe/client"
	"github.com/SenseUnit/dtlspipe/keystore"
	"github.com/SenseUnit/dtlspipe/server"
	"github.com/SenseUnit/dtlspipe/util"
	"github.com/Snawoot/rlzone"
)

const (
	ProgName     = "dtlspipe"
	PSKEnvVarKey = "DTLSPIPE_PSK"
)

type cipherlistArg struct {
	Value ciphers.CipherList
}

func (l *cipherlistArg) String() string {
	return ciphers.CipherListToString(l.Value)
}

func (l *cipherlistArg) Set(s string) error {
	parsed, err := ciphers.StringToCipherList(s)
	if err != nil {
		return fmt.Errorf("can't parse cipher list: %w", err)
	}
	l.Value = parsed
	return nil
}

type curvelistArg struct {
	Value ciphers.CurveList
}

func (l *curvelistArg) String() string {
	return ciphers.CurveListToString(l.Value)
}

func (l *curvelistArg) Set(s string) error {
	parsed, err := ciphers.StringToCurveList(s)
	if err != nil {
		return fmt.Errorf("can't parse curve list: %w", err)
	}
	l.Value = parsed
	return nil
}

type timelimitArg struct {
	low  time.Duration
	high time.Duration
}

func (a *timelimitArg) String() string {
	if a.low == a.high {
		return a.low.String()
	}
	return fmt.Sprintf("%s-%s", a.low.String(), a.high.String())
}

func (a *timelimitArg) Set(s string) error {
	parts := strings.SplitN(s, "-", 2)
	switch len(parts) {
	case 1:
		dur, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		a.low, a.high = dur, dur
		return nil
	case 2:
		durLow, err := time.ParseDuration(parts[0])
		if err != nil {
			return fmt.Errorf("first component parse failed: %w", err)
		}
		durHigh, err := time.ParseDuration(parts[1])
		if err != nil {
			return fmt.Errorf("second component parse failed: %w", err)
		}
		a.low, a.high = durLow, durHigh
		return nil
	default:
		return errors.New("unexpected number of components")
	}
}

type ratelimitArg struct {
	value rlzone.Ratelimiter[netip.Addr]
}

func (r *ratelimitArg) String() string {
	if r == nil || r.value == nil {
		return ""
	}
	return r.value.String()
}

func (r *ratelimitArg) Set(s string) error {
	if s == "" {
		r.value = nil
		return nil
	}
	rl, err := rlzone.FromString[netip.Addr](s)
	if err != nil {
		return err
	}
	r.value = rl
	return nil
}

var (
	version = "undefined"

	timeout         = flag.Duration("timeout", 10*time.Second, "network operation timeout")
	idleTime        = flag.Duration("idle-time", 30*time.Second, "max idle time for UDP session")
	pskHexOpt       = flag.String("psk", "", "hex-encoded pre-shared key. Can be generated with genpsk subcommand")
	keyLength       = flag.Uint("key-length", 16, "generate key with specified length")
	identity        = flag.String("identity", "", "client identity sent to server")
	mtu             = flag.Int("mtu", 1400, "MTU used for DTLS fragments")
	cpuprofile      = flag.String("cpuprofile", "", "write cpu profile to file")
	skipHelloVerify = flag.Bool("skip-hello-verify", true, "(server only) skip hello verify request. Useful to workaround DPI")
	connectionIDExt = flag.Bool("cid", true, "enable connection_id extension")
	ciphersuites    = cipherlistArg{}
	curves          = curvelistArg{}
	staleMode       = util.EitherStale
	timeLimit       = timelimitArg{}
	rateLimit       = ratelimitArg{rlzone.Must(rlzone.NewSmallest[netip.Addr](1*time.Minute, 20))}
)

func init() {
	flag.Var(&ciphersuites, "ciphers", "colon-separated list of ciphers to use")
	flag.Var(&curves, "curves", "colon-separated list of curves to use")
	flag.Var(&staleMode, "stale-mode", "which stale side of connection makes whole session stale (both, either, left, right)")
	flag.Var(&rateLimit, "rate-limit", "limit for incoming connections rate. Format: <limit>/<time duration> or empty string to disable")
	flag.Var(&timeLimit, "time-limit", "limit for each session `duration`. Use single value X for fixed limit or range X-Y for randomized limit")
}

func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "%s [OPTION]... server <BIND ADDRESS> <REMOTE ADDRESS>\n", ProgName)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "  Run server listening on BIND ADDRESS for DTLS datagrams and forwarding decrypted UDP datagrams to REMOTE ADDRESS.")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "%s [OPTION]... client <BIND ADDRESS> <REMOTE ADDRESS>\n", ProgName)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "  Run client listening on BIND ADDRESS for UDP datagrams and forwarding encrypted DTLS datagrams to REMOTE ADDRESS.")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "%s [OPTION]... hoppingclient <BIND ADDRESS> <ENDPOINT GROUP> [ENDPOINT GROUP]...\n", ProgName)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "  Run client listening on BIND ADDRESS for UDP datagrams and forwarding encrypted DTLS datagrams to a random chosen endpoints.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "  Endpoints are specified by a list of one or more ENDPOINT GROUP. ENDPOINT GROUP syntax is defined by following ABNF:")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "    ENDPOINT-GROUP = address-term *( \",\" address-term ) \":\" Port")
	fmt.Fprintln(out, "    address-term = Domain / IP-range / IP-prefix / IP-address")
	fmt.Fprintln(out, "    Domain = <Defined in Section 4.1.2 of [RFC5321]>")
	fmt.Fprintln(out, "    IP-range = ( IPv4address \"..\" IPv4address ) / ( IPv6address \"..\" IPv6address )")
	fmt.Fprintln(out, "    IP-prefix = IP-address \"/\" 1*DIGIT")
	fmt.Fprintln(out, "    IP-address = IPv6address / IPv4address")
	fmt.Fprintln(out, "    IPv4address = <Defined in Section 4.1 of [RFC5954]>")
	fmt.Fprintln(out, "    IPv6address = <Defined in Section 4.1 of [RFC5954]>")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "  Endpoint is chosen randomly as follows.")
	fmt.Fprintln(out, "  First, random ENDPOINT GROUP is chosen with equal probability.")
	fmt.Fprintln(out, "  Next, address is chosen from address sets specified by that group, with probability")
	fmt.Fprintln(out, "  proportional to size of that set. Domain names and single addresses condidered ")
	fmt.Fprintln(out, "  as sets having size 1, ranges and prefixes have size as count of addresses in it.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "  Example: 'example.org:20000-50000' '192.168.0.0/16,10.0.0.0/8,172.16.0.0-172.31.255.255:50000-60000'")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "%s [OPTION]... genpsk\n", ProgName)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "  Generate and output PSK.")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "%s ciphers\n", ProgName)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "  Print list of supported ciphers and exit.")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "%s curves\n", ProgName)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "  Print list of supported elliptic curves and exit.")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "%s version\n", ProgName)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "  Print program version and exit.")
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
	psk, err := simpleGetPSK()
	if err != nil {
		log.Printf("can't get PSK: %v", err)
		return 2
	}
	log.Printf("starting dtlspipe client: %s =[wrap into DTLS]=> %s", bindAddress, remoteAddress)
	defer log.Println("dtlspipe client stopped")

	appCtx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cfg := client.Config{
		BindAddress: bindAddress,
		RemoteDialFunc: util.NewDynDialer(
			addrgen.SingleEndpoint(remoteAddress).Endpoint,
		).DialContext,
		PSKCallback:    keystore.NewStaticKeystore(psk).PSKCallback,
		PSKIdentity:    *identity,
		Timeout:        *timeout,
		IdleTimeout:    *idleTime,
		BaseContext:    appCtx,
		MTU:            *mtu,
		CipherSuites:   ciphersuites.Value,
		EllipticCurves: curves.Value,
		StaleMode:      staleMode,
		TimeLimitFunc:  util.TimeLimitFunc(timeLimit.low, timeLimit.high),
		AllowFunc:      util.AllowByRatelimit(rateLimit.value),
		EnableCID:      *connectionIDExt,
	}

	clt, err := client.New(&cfg)
	if err != nil {
		log.Fatalf("client startup failed: %v", err)
	}
	defer clt.Close()

	<-appCtx.Done()

	return 0
}

func cmdHoppingClient(args []string) int {
	bindAddress := args[0]
	args = args[1:]
	psk, err := simpleGetPSK()
	if err != nil {
		log.Printf("can't get PSK: %v", err)
		return 2
	}
	log.Printf("starting dtlspipe client: %s =[wrap into DTLS]=> %v", bindAddress, args)
	defer log.Println("dtlspipe client stopped")

	appCtx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	gen, err := addrgen.EqualMultiEndpointGenFromSpecs(args)
	if err != nil {
		log.Printf("can't construct generator: %v", err)
		return 2
	}

	cfg := client.Config{
		BindAddress: bindAddress,
		RemoteDialFunc: util.NewDynDialer(
			func() string {
				ep := gen.Endpoint()
				log.Printf("selected new endpoint %s", ep)
				return ep
			},
		).DialContext,
		PSKCallback:    keystore.NewStaticKeystore(psk).PSKCallback,
		PSKIdentity:    *identity,
		Timeout:        *timeout,
		IdleTimeout:    *idleTime,
		BaseContext:    appCtx,
		MTU:            *mtu,
		CipherSuites:   ciphersuites.Value,
		EllipticCurves: curves.Value,
		StaleMode:      staleMode,
		TimeLimitFunc:  util.TimeLimitFunc(timeLimit.low, timeLimit.high),
		AllowFunc:      util.AllowByRatelimit(rateLimit.value),
		EnableCID:      *connectionIDExt,
	}

	clt, err := client.New(&cfg)
	if err != nil {
		log.Fatalf("client startup failed: %v", err)
	}
	defer clt.Close()

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
		BindAddress:     bindAddress,
		RemoteAddress:   remoteAddress,
		PSKCallback:     keystore.NewStaticKeystore(psk).PSKCallback,
		Timeout:         *timeout,
		IdleTimeout:     *idleTime,
		BaseContext:     appCtx,
		MTU:             *mtu,
		SkipHelloVerify: *skipHelloVerify,
		CipherSuites:    ciphersuites.Value,
		EllipticCurves:  curves.Value,
		StaleMode:       staleMode,
		TimeLimitFunc:   util.TimeLimitFunc(timeLimit.low, timeLimit.high),
		AllowFunc:       util.AllowByRatelimit(rateLimit.value),
		EnableCID:       *connectionIDExt,
	}

	srv, err := server.New(&cfg)
	if err != nil {
		log.Fatalf("server startup failed: %v", err)
	}
	defer srv.Close()

	<-appCtx.Done()
	return 0
}

func cmdCiphers() int {
	for _, id := range ciphers.FullCipherList {
		fmt.Println(ciphers.CipherIDToString(id))
	}
	return 0
}

func cmdCurves() int {
	for _, curve := range ciphers.FullCurveList {
		fmt.Println(ciphers.CurveIDToString(curve))
	}
	return 0
}

func run() int {
	flag.CommandLine.Usage = usage
	flag.Parse()
	args := flag.Args()

	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	switch len(args) {
	case 0:
		usage()
		return 2
	case 1:
		switch args[0] {
		case "genpsk":
			return cmdGenPSK()
		case "ciphers":
			return cmdCiphers()
		case "curves":
			return cmdCurves()
		case "version":
			return cmdVersion()
		}
	case 2:
		usage()
		return 2
	case 3:
		switch args[0] {
		case "server":
			return cmdServer(args[1], args[2])
		case "client":
			return cmdClient(args[1], args[2])
		}
	}
	switch args[0] {
	case "hoppingclient":
		return cmdHoppingClient(args[1:])
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
