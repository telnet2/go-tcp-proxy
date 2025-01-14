package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	proxy "github.com/telnet2/go-tcp-proxy"
)

var (
	version = "0.0.0-src"
	matchid = uint64(0)
	connid  = uint64(0)
	logger  proxy.ColorLogger

	localAddr   = flag.String("l", ":9999", "local address")
	remoteAddr  = flag.String("r", "localhost:80", "remote address")
	verbose     = flag.Bool("v", false, "display server actions")
	veryverbose = flag.Bool("vv", false, "display server actions and all tcp data")
	nagles      = flag.Bool("n", false, "disable nagles algorithm")
	hex         = flag.Bool("h", false, "output hex")
	rawBytes    = flag.Bool("raw", false, "output raw bytes")
	h2          = flag.Bool("h2", false, "output as HTTP/2 frames")
	inbound     = flag.String("inbound", "", "file to write inbound (local to remote) traffic")
	outbound    = flag.String("outbound", "", "file to write outbound (remote to local) traffic")

	colors    = flag.Bool("c", false, "output ansi colors")
	unwrapTLS = flag.Bool("unwrap-tls", false, "remote connection with TLS exposed unencrypted locally")
	match     = flag.String("match", "", "match regex (in the form 'regex')")
	replace   = flag.String("replace", "", "replace regex (in the form 'regex~replacer')")
)

func main() {
	flag.Parse()

	logger := proxy.ColorLogger{
		Verbose: *verbose,
		Color:   *colors,
	}

	logger.Info("go-tcp-proxy (%s) proxing from %v to %v ", version, *localAddr, *remoteAddr)

	laddr, err := net.ResolveTCPAddr("tcp", *localAddr)
	if err != nil {
		logger.Warn("Failed to resolve local address: %s", err)
		os.Exit(1)
	}
	raddr, err := net.ResolveTCPAddr("tcp", *remoteAddr)
	if err != nil {
		logger.Warn("Failed to resolve remote address: %s", err)
		os.Exit(1)
	}
	listener, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		logger.Warn("Failed to open local port to listen: %s", err)
		os.Exit(1)
	}

	matcher := createMatcher(*match)
	replacer := createReplacer(*replace)

	if *veryverbose {
		*verbose = true
	}

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			logger.Warn("Failed to accept connection '%s'", err)
			continue
		}
		connid++

		var p *proxy.Proxy
		if *unwrapTLS {
			logger.Info("Unwrapping TLS")
			p = proxy.NewTLSUnwrapped(conn, laddr, raddr, *remoteAddr)
		} else {
			p = proxy.New(conn, laddr, raddr)
		}

		if *inbound != "" {
			ibf, err := os.Create(*inbound)
			if err != nil {
				logger.Warn("inbound file error: %v", err)
			} else {
				p.SetInboundFile(ibf)
			}
		}

		if *outbound != "" {
			obf, err := os.Create(*outbound)
			if err != nil {
				logger.Warn("inbound file error: %v", err)
			} else {
				p.SetOutboundFile(obf)
			}
		}

		p.Matcher = matcher
		p.Replacer = replacer

		p.Nagles = *nagles
		p.OutputHex = *hex
		p.OutputRawBytes = *rawBytes
		p.H2 = *h2
		p.Log = proxy.ColorLogger{
			Verbose:     *verbose,
			VeryVerbose: *veryverbose,
			Prefix:      fmt.Sprintf("Connection #%03d ", connid),
			Color:       *colors,
		}

		go p.Start()
	}
}

func createMatcher(match string) func([]byte) {
	if match == "" {
		return nil
	}
	re, err := regexp.Compile(match)
	if err != nil {
		logger.Warn("Invalid match regex: %s", err)
		return nil
	}

	logger.Info("Matching %s", re.String())
	return func(input []byte) {
		ms := re.FindAll(input, -1)
		for _, m := range ms {
			matchid++
			logger.Info("Match #%d: %s", matchid, string(m))
		}
	}
}

func createReplacer(replace string) func([]byte) []byte {
	if replace == "" {
		return nil
	}
	//split by / (TODO: allow slash escapes)
	parts := strings.Split(replace, "~")
	if len(parts) != 2 {
		logger.Warn("Invalid replace option")
		return nil
	}

	re, err := regexp.Compile(string(parts[0]))
	if err != nil {
		logger.Warn("Invalid replace regex: %s", err)
		return nil
	}

	repl := []byte(parts[1])

	logger.Info("Replacing %s with %s", re.String(), repl)
	return func(input []byte) []byte {
		return re.ReplaceAll(input, repl)
	}
}
