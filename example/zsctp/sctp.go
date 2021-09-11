package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	sctp "github.com/ishidawataru/sctp"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/config"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/sirupsen/logrus"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

var servicePtr *string
var configPtr *string
var service string
var lport *int
var ip *string
var port *int
var sndbuf *int
var rcvbuf *int
var bufsize *int

func serveClient(conn net.Conn, bufsize int) error {
	var context ziti.Context
	if len(*configPtr) > 0 {
		file := *configPtr
		configFile, err := config.NewFromFile(file)
		if err != nil {
			logrus.WithError(err).Error("Error loading config file")
			os.Exit(1)
		}
		context = ziti.NewContextWithConfig(configFile)
	} else {
		context = ziti.NewContext()
	}
	dialOptions := &ziti.DialOptions{
		ConnectTimeout: 1 * time.Minute,
		//AppData:        []byte("hi there"),
	}
	//dial ziti service with options specified in dialOptions
	zconn, err := context.DialWithOptions(service, dialOptions)
	if err != nil {
		logrus.WithError(err).Error("Error dialing service")
		os.Exit(1)
	}
	for {
		buf := make([]byte, bufsize+128) //  overhead of SCTPSndRvInfoWrappedConn
		now := time.Now()
		conn.SetReadDeadline(now.Add(time.Second * 1))
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("read failed: %v", err)
			return err
		}
		message := buf[:n]
		fmt.Println(message)
		streamid0 := strconv.FormatInt(int64(message[1]), 16)
		streamid1 := strconv.FormatInt(int64(message[0]), 16)
		streamidS := streamid0 + streamid1
		streamid, err := strconv.ParseUint(streamidS, 16, 64)
		if err != nil {
			log.Printf("read: %v", err)
			return err
		}
		ppid0 := strconv.FormatInt(int64(message[11]), 16)
		ppid1 := strconv.FormatInt(int64(message[10]), 16)
		ppid2 := strconv.FormatInt(int64(message[9]), 16)
		ppid3 := strconv.FormatInt(int64(message[8]), 16)
		ppidS := ppid0 + ppid1 + ppid2 + ppid3
		ppid, err := strconv.ParseUint(ppidS, 16, 64)
		if err != nil {
			log.Printf("read: %v", err)
			return err
		}

		bytesPpid := message[8:12]
		bytesStream := message[0:2]
		header := append(bytesStream, bytesPpid...)
		payload := message[33:n]
		packet := append(header, payload...)
		if _, err := zconn.Write(packet); err != nil {
			panic(err)
		}
		zbuf := make([]byte, 1500)
		now = time.Now()
		zconn.SetReadDeadline(now.Add(time.Second * 1))
		zn, err := zconn.Read(zbuf)
		if err != nil {
			_ = conn.Close()
			return err
		}
		fmt.Printf("stream: %v, ppid: %v, payload: %v\n", streamid, ppid, payload)
		log.Printf("read: %v", n)
		log.Printf("zbuf: %v", zbuf[:zn])
		n, err = conn.Write(zbuf[:zn])
		if err != nil {
			log.Printf("write failed: %v", err)
			return err
		}
		log.Printf("write: %d", n)
	}
}

func handleSctp(zconn net.Conn, ips []net.IPAddr) error {
	addr := &sctp.SCTPAddr{
		IPAddrs: ips,
		Port:    *port,
	}
	var laddr *sctp.SCTPAddr
	if *lport != 0 {
		laddr = &sctp.SCTPAddr{
			Port: *lport,
		}
	}

	conn, err := sctp.DialSCTP("sctp", laddr, addr)
	if err != nil {
		log.Fatalf("failed to dial: %v", err)
	}

	log.Printf("Dail LocalAddr: %s; RemoteAddr: %s", conn.LocalAddr(), conn.RemoteAddr())

	if *sndbuf != 0 {
		err = conn.SetWriteBuffer(*sndbuf)
		if err != nil {
			log.Fatalf("failed to set write buf: %v", err)
		}
	}
	if *rcvbuf != 0 {
		err = conn.SetReadBuffer(*rcvbuf)
		if err != nil {
			log.Fatalf("failed to set read buf: %v", err)
		}
	}

	*sndbuf, err = conn.GetWriteBuffer()
	if err != nil {
		log.Fatalf("failed to get write buf: %v", err)
	}
	*rcvbuf, err = conn.GetReadBuffer()
	if err != nil {
		log.Fatalf("failed to get read buf: %v", err)
	}
	log.Printf("SndBufSize: %d, RcvBufSize: %d", *sndbuf, *rcvbuf)

	for {
		zbuf := make([]byte, *bufsize)
		now := time.Now()
		zconn.SetReadDeadline(now.Add(time.Second * 1))
		zn, err := zconn.Read(zbuf)
		if err != nil {
			_ = conn.Close()
			return err
		}
		msg := zbuf[:zn]

		streamid0 := strconv.FormatInt(int64(msg[1]), 16)
		streamid1 := strconv.FormatInt(int64(msg[0]), 16)
		streamidS := streamid0 + streamid1
		streamid, err := strconv.ParseUint(streamidS, 16, 64)
		if err != nil {
			log.Printf("read: %v", err)
			return err
		}
		ppid0 := strconv.FormatInt(int64(msg[5]), 16)
		ppid1 := strconv.FormatInt(int64(msg[4]), 16)
		ppid2 := strconv.FormatInt(int64(msg[3]), 16)
		ppid3 := strconv.FormatInt(int64(msg[2]), 16)
		ppidS := ppid0 + ppid1 + ppid2 + ppid3
		ppid, err := strconv.ParseUint(ppidS, 16, 64)
		if err != nil {
			log.Printf("read: %v", err)
			return err
		}

		info := &sctp.SndRcvInfo{
			Stream: uint16(streamid),
			PPID:   uint32(ppid),
		}
		//ppid += 1
		conn.SubscribeEvents(sctp.SCTP_EVENT_DATA_IO)
		buf := make([]byte, *bufsize)
		if err != nil {
			log.Printf("cant make random: %v", err)
		}
		zn, err = conn.SCTPWrite(msg[6:], info)
		if err != nil {
			log.Fatalf("failed to write: %v", err)
		}
		log.Printf("write: len %d", zn)
		now = time.Now()
		conn.SetReadDeadline(now.Add(time.Second * 1))
		//n, info, err := conn.SCTPRead(buf)
		n, info, err := conn.SCTPRead(buf)
		if err != nil {
			log.Fatalf("failed to read: %v", err)
		}
		message := new(bytes.Buffer)
		binary.Write(message, binary.BigEndian, info.Stream)
		binary.Write(message, binary.BigEndian, info.SSN)
		binary.Write(message, binary.BigEndian, uint32(0))
		binary.Write(message, binary.BigEndian, info.PPID)
		binary.Write(message, binary.BigEndian, uint64(0))
		binary.Write(message, binary.BigEndian, info.TSN)
		binary.Write(message, binary.BigEndian, uint32(0))
		binary.Write(message, binary.BigEndian, uint32(0))
		binary.Write(message, binary.LittleEndian, buf[:n])
		packet := message.Bytes()
		fmt.Printf("packet", packet)
		log.Printf("read: len %d, info: %+v", n, info)
		if _, err := zconn.Write(packet); err != nil {
			logrus.WithError(err).Error("failed to write. closing connection")
			_ = conn.Close()
		}
		time.Sleep(time.Second)
	}
}

func main() {
	var server = flag.Bool("server", false, "")
	ip = flag.String("ip", "0.0.0.0", "")
	port = flag.Int("port", 0, "")
	lport = flag.Int("lport", 0, "")
	bufsize = flag.Int("bufsize", 256, "")
	sndbuf = flag.Int("sndbuf", 0, "")
	rcvbuf = flag.Int("rcvbuf", 0, "")
	servicePtr = flag.String("s", "sctp-trans", "Name of Service")
	configPtr = flag.String("c", "", "Name of config file")
	flag.Parse()

	ips := []net.IPAddr{}

	for _, i := range strings.Split(*ip, ",") {
		if a, err := net.ResolveIPAddr("ip", i); err == nil {
			log.Printf("Resolved address '%s' to %s", i, a)
			ips = append(ips, *a)
		} else {
			log.Printf("Error resolving address '%s': %v", i, err)
		}
	}
	if len(*servicePtr) > 0 {
		service = *servicePtr
	} else {
		service = "ziti-sctp"
	}
	addr := &sctp.SCTPAddr{
		IPAddrs: ips,
		Port:    *port,
	}
	log.Printf("raw addr: %+v\n", addr.ToRawSockAddrBuf())

	if *server {
		ln, err := sctp.ListenSCTP("sctp", addr)
		if err != nil {
			log.Fatalf("failed to listen: %v", err)
		}
		log.Printf("Listen on %s", ln.Addr())

		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Fatalf("failed to accept: %v", err)
			}
			log.Printf("Accepted Connection from RemoteAddr: %s", conn.RemoteAddr())
			wconn := sctp.NewSCTPSndRcvInfoWrappedConn(conn.(*sctp.SCTPConn))

			if *sndbuf != 0 {
				err = wconn.SetWriteBuffer(*sndbuf)
				if err != nil {
					log.Fatalf("failed to set write buf: %v", err)
				}
			}
			if *rcvbuf != 0 {
				err = wconn.SetReadBuffer(*rcvbuf)
				if err != nil {
					log.Fatalf("failed to set read buf: %v", err)
				}
			}
			*sndbuf, err = wconn.GetWriteBuffer()
			if err != nil {
				log.Fatalf("failed to get write buf: %v", err)
			}
			*rcvbuf, err = wconn.GetWriteBuffer()
			if err != nil {
				log.Fatalf("failed to get read buf: %v", err)
			}
			log.Printf("SndBufSize: %d, RcvBufSize: %d", *sndbuf, *rcvbuf)

			go serveClient(wconn, *bufsize)
		}

	} else {
		logger := pfxlog.Logger()
		options := ziti.ListenOptions{
			ConnectTimeout:        10 * time.Second,
			MaxConnections:        3,
			BindUsingEdgeIdentity: true,
		}
		logger.Infof("binding service %v\n", service)
		var listener edge.Listener
		if len(*configPtr) > 0 {
			file := *configPtr
			configFile, err := config.NewFromFile(file)
			if err != nil {
				logrus.WithError(err).Error("Error loading config file")
				os.Exit(1)
			}
			context := ziti.NewContextWithConfig(configFile)
			identity, err := context.GetCurrentIdentity()
			if err != nil {
				logrus.WithError(err).Error("Error resolving local Identity")
				os.Exit(1)
			}
			fmt.Printf("\n%+v now serving\n\n", identity.Name)
			listener, err = context.ListenWithOptions(service, &options)
			if err != nil {
				logrus.WithError(err).Error("Error Binding Service")
				os.Exit(1)
			}
		} else {
			context := ziti.NewContext()
			identity, err := context.GetCurrentIdentity()
			if err != nil {
				logrus.WithError(err).Error("Error resolving local Identity")
				os.Exit(1)
			}
			fmt.Printf("\n%+v now serving\n\n", identity.Name)
			listener, err = context.ListenWithOptions(service, &options)
			if err != nil {
				logrus.WithError(err).Error("Error Binding Service")
				os.Exit(1)
			}
		}
		for {
			conn, err := listener.Accept()
			if err != nil {
				logrus.WithError(err).Error("Problem accepting connection, sleeping for 5 Seconds")
				time.Sleep(time.Duration(5) * time.Second)
			}
			logger.Infof("new connection")
			fmt.Println()
			go handleSctp(conn, ips)
		}

	}
}
