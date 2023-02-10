package proxy

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// Proxy - Manages a Proxy connection, piping data between local and remote.
type Proxy struct {
	sentBytes     uint64
	receivedBytes uint64
	laddr, raddr  *net.TCPAddr
	lconn, rconn  io.ReadWriteCloser
	erred         bool
	errsig        chan bool
	tlsUnwrapp    bool
	tlsAddress    string
	ibf, obf      *os.File

	Matcher  func([]byte)
	Replacer func([]byte) []byte

	// Settings
	Nagles         bool
	Log            Logger
	OutputHex      bool
	OutputRawBytes bool
	H2             bool
}

// New - Create a new Proxy instance. Takes over local connection passed in,
// and closes it when finished.
func New(lconn *net.TCPConn, laddr, raddr *net.TCPAddr) *Proxy {
	return &Proxy{
		lconn:  lconn,
		laddr:  laddr,
		raddr:  raddr,
		erred:  false,
		errsig: make(chan bool),
		Log:    NullLogger{},
	}
}

// NewTLSUnwrapped - Create a new Proxy instance with a remote TLS server for
// which we want to unwrap the TLS to be able to connect without encryption
// locally
func NewTLSUnwrapped(lconn *net.TCPConn, laddr, raddr *net.TCPAddr, addr string) *Proxy {
	p := New(lconn, laddr, raddr)
	p.tlsUnwrapp = true
	p.tlsAddress = addr
	return p
}

type setNoDelayer interface {
	SetNoDelay(bool) error
}

func (p *Proxy) SetInboundFile(f *os.File) {
	p.ibf = f
}

func (p *Proxy) SetOutboundFile(f *os.File) {
	p.obf = f
}

// Start - open connection to remote and start proxying data.
func (p *Proxy) Start() {
	defer p.lconn.Close()

	var err error
	//connect to remote
	if p.tlsUnwrapp {
		p.rconn, err = tls.Dial("tcp", p.tlsAddress, nil)
	} else {
		p.rconn, err = net.DialTCP("tcp", nil, p.raddr)
	}
	if err != nil {
		p.Log.Warn("Remote connection failed: %s", err)
		return
	}
	defer p.rconn.Close()

	//nagles?
	if p.Nagles {
		if conn, ok := p.lconn.(setNoDelayer); ok {
			conn.SetNoDelay(true)
		}
		if conn, ok := p.rconn.(setNoDelayer); ok {
			conn.SetNoDelay(true)
		}
	}

	//display both ends
	p.Log.Info("Opened %s >>> %s", p.laddr.String(), p.raddr.String())

	//bidirectional copy
	go p.pipe(p.lconn, p.rconn, p.ibf)
	go p.pipe(p.rconn, p.lconn, p.obf)

	//wait for close...
	<-p.errsig
	p.Log.Info("Closed (%d bytes sent, %d bytes recieved)", p.sentBytes, p.receivedBytes)
}

func (p *Proxy) err(s string, err error) {
	if p.erred {
		return
	}
	if err != io.EOF {
		p.Log.Warn(s, err)
	}
	p.errsig <- true
	p.erred = true
}

func (p *Proxy) pipe(src, dst io.ReadWriter, f *os.File) {
	islocal := src == p.lconn

	var dataDirection string
	if islocal {
		dataDirection = ">>> %d bytes sent%s"
	} else {
		dataDirection = "<<< %d bytes recieved%s"
	}

	var byteFormat string
	if p.OutputHex {
		byteFormat = "%x"
	} else if p.OutputRawBytes {
		byteFormat = "%v"
	} else {
		byteFormat = "%s"
	}

	if p.H2 {
		dir := "<<"
		if islocal {
			dir = ">>"
		}

		w := io.MultiWriter(&bytesWriter{w: os.Stdout, prefix: dir}, dst)
		tr := io.TeeReader(src, w)

		if islocal {
			preface := make([]byte, 24)
			n, err := tr.Read(preface)
			if err != nil || n < len(preface) {
				p.err("Read failed for preface: %v", err)
				return
			}
			http2preface, _ := hex.DecodeString("505249202a20485454502f322e300d0a0d0a534d0d0a0d0a")
			if !bytes.Equal(preface, http2preface) {
				p.err("not an HTTP/2 preface: %v", errors.New(string(preface)))
				return
			}
		}

		fr := http2.NewFramer(nil, tr)
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				fmt.Printf("%s read frame error: %v\n", dir, err)
				return
			}

			switch hf := f.(type) {
			case *http2.SettingsFrame:
				fmt.Println(dir, "Settings frame:", hf.String())
				for i := 0; i < hf.NumSettings(); i++ {
					fmt.Println(hf.Setting(i).String())
				}
			case *http2.HeadersFrame:
				fmt.Println(dir, "Headers frame:", hf.String())
				decoder := hpack.NewDecoder(2048, nil)
				fields, _ := decoder.DecodeFull(hf.HeaderBlockFragment())
				for _, f := range fields {
					fmt.Println(f.String())
				}
			case *http2.DataFrame:
				fmt.Println(dir, "Data frame:", hf.String(), hf.Data())
			case *http2.PingFrame:
				fmt.Println(dir, "Ping frame:", hf.String())
			case *http2.WindowUpdateFrame:
				fmt.Println(dir, "Window-update frame:", hf.String())
			}
		}
	} else {
		//directional copy (64k buffer)
		tr := io.TeeReader(src, io.MultiWriter(&bytesWriter{w: os.Stdout}, dst))
		buff := make([]byte, 0xffff)
		for {
			n, err := tr.Read(buff)
			if err != nil {
				p.err("Read failed '%s'\n", err)
				return
			}
			b := buff[:n]

			//execute match
			if p.Matcher != nil {
				p.Matcher(b)
			}

			//execute replace
			if p.Replacer != nil {
				b = p.Replacer(b)
			}

			//show output
			p.Log.Debug(dataDirection, n, "")
			if byteFormat == "%s" {
				p.Log.Trace("%s", string(b))
			} else {
				p.Log.Trace(byteFormat, b)
			}

			//write out result
			// n, err = dst.Write(b)
			// if err != nil {
			// 	p.err("Write failed '%s'\n", err)
			// 	return
			// }

			// if f != nil {
			// 	_, _ = f.Write(b)
			// }
			if islocal {
				p.sentBytes += uint64(n)
			} else {
				p.receivedBytes += uint64(n)
			}
		}
	}
}

var _ io.Writer = &bytesWriter{}

type bytesWriter struct {
	w      io.Writer
	prefix string
}

func (bw *bytesWriter) Write(b []byte) (n int, err error) {
	nn := 0
	for nn < len(b) {
		n, err := fmt.Fprintf(bw.w, "[%s] %v\n", bw.prefix, b)
		nn += n
		if err != nil {
			return nn, err
		}
	}
	return len(b), nil
}
