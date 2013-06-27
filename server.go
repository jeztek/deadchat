package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
)

func error_(err error, r int) {
	fmt.Printf("Error: %v\n", err)
	if r >= 0 {
		os.Exit(r)
	}
}

type clientMap map[string]net.Conn

func (cm clientMap) Write(buf []byte) (n int, err error) {
	for _, c := range cm {
		go c.Write(buf)
	}
	n = len(buf)
	return
}

func (cm clientMap) Add(name string, c net.Conn) bool {
	_, present := cm[name]
	if present {
		return false
	}
	cm[name] = c
	return true
}

const HEADER_BYTE byte = '\xde'

const (
	// Commands from client
	CMD_MSGALL = iota
	CMD_MSGTO
	CMD_IDENT
	CMD_AUTH
	CMD_GETPK
	CMD_WHO

	// Responses from server
	SVR_NOTICE
	SVR_MSG
	SVR_IDENT
	SVR_AUTH_VALID
	SVR_PK
	SVR_WHO
)

type ClientInfo struct {
	conn net.Conn
	name string
}

var clients clientMap

func init() {
	clients = make(clientMap)
}

// Packet:
// [header] [packet len except header (4)] [type (1)] [packet data]
func client(c net.Conn) {
	defer c.Close()

	var info ClientInfo
	info.conn = c

	br := bufio.NewReader(c)
	
	for {
		_, err := br.ReadBytes(HEADER_BYTE)
		if err != nil {
			break
		}

		packet := make([]byte, 4)
		read_bytes := 0
		for read_bytes < 4 {
			tmp := make([]byte, 4)
			nread, err := br.Read(tmp)
			if err != nil {
				break
			}
			copy(packet[read_bytes:], tmp[:nread])
			read_bytes += nread
		}
		
		pktlen := int(binary.BigEndian.Uint32(packet))
		packet = make([]byte, pktlen)
		read_bytes = 0
		for read_bytes < pktlen {
			tmp := make([]byte, pktlen)
			nread, err := br.Read(tmp)
			if err != nil {
				break
			}
			copy(packet[read_bytes:], tmp[:nread])
			read_bytes += nread
		}

		parse(&info, packet)
	}
	svr_notice_all(info.name + " disconnected")
}

func parse(info *ClientInfo, packet []byte) {
	fmt.Printf("rx: ")
	for i := 0; i < len(packet); i++ {
		fmt.Printf("%02x ", packet[i])
	}
	fmt.Printf("\n")

	cmd := packet[0]
	switch {
	case cmd == CMD_MSGALL:
		if info.name == "" {
			svr_notice(info.conn, "name not set")
		} else {
			cmd_msgall(info.name, packet[1:])
		}
	case cmd == CMD_IDENT:
		cmd_ident(info, packet[1:])
		fmt.Printf("name: %s\n", info.name)
	default:
	}
}

func packetize(packet_type byte, payload []byte) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{ HEADER_BYTE })
	binary.Write(&buf, binary.BigEndian, uint32(len(payload)+1))
	buf.Write([]byte{ packet_type })
	buf.Write(payload)

	var pkt []byte = buf.Bytes()
	fmt.Printf("tx: ")
	for i := 0; i < len(pkt); i++ {
		fmt.Printf("%02x ", pkt[i])
	}
	fmt.Printf("\n")
	return buf.Bytes()
}

func svr_notice(c net.Conn, msg string) (int, error) {
	return c.Write(packetize(byte(SVR_NOTICE), []byte(msg)))
}

func svr_notice_all(msg string) (int, error) {
	return clients.Write(packetize(byte(SVR_NOTICE), []byte(msg)))
}

func svr_auth_valid(c net.Conn) (int, error) {
	return c.Write(packetize(byte(SVR_AUTH_VALID), []byte{}))
}

func cmd_msgall(sender string, data []byte) (int, error) {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint16(len(sender)))
	buf.Write([]byte(sender))
	buf.Write(data)
	return clients.Write(packetize(SVR_MSG, buf.Bytes()))
}

func cmd_ident(info *ClientInfo, data []byte) {
	name := string(data)

	if len(name) > 65535 {
		svr_notice(info.conn, "invalid name")
		return
	}

	if !clients.Add(name, info.conn) {
		svr_notice(info.conn, name + " is already connected")
		return
	}

	svr_auth_valid(info.conn)
	svr_notice_all(name + " connected")
	info.name = name
}

func main() {
	var (
		port int
		help bool
	)
	flag.IntVar(&port, "port", 4000, "Port to listen on")
	flag.BoolVar(&help, "help", false, "Display this")
	flag.Parse()

	if help {
		flag.Usage()
		return
	}

	fmt.Printf("Listening for clients on port %v\n", port)
	lis, err := net.Listen("tcp", fmt.Sprintf(":%v", port))
	if err != nil {
		error_(err, 1)
	}

	for {
		c, err := lis.Accept()
		if err != nil {
			error_(err, -1)
			continue
		}

		go client(c)
	}
}
