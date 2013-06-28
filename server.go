// TODO: disconnect user if name not set

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
const MAX_NAME_LENGTH int = 65535

// All packets have the following format:
// [header (1)] [packet length (4)] [type (1)] [payload]
//
// The packet length field specifies the number of bytes in the packet
// excluding the header
//
// The payload varies for each command or response
//
const (
	// Commands from client
	CMD_MSGALL = iota	// [data]
	CMD_MSGTO			// [target name length (2)] [target name] [data] 
	CMD_IDENT			// [name]
	CMD_WHO

	// Responses from server
	SVR_NOTICE			// [plaintext message]
	SVR_MSG				// [sender name length (2)] [sender name] [data]
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
// [header] [packet length excluding header (4)] [type (1)] [packet data]
func client(c net.Conn) {
	defer c.Close()

	var info ClientInfo
	info.conn = c

	br := bufio.NewReader(c)
	
	for {
		// Drop bytes preceding HEADER_BYTE
		_, err := br.ReadBytes(HEADER_BYTE)
		if err != nil {
			break
		}

		// Get packet length field
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

		// Get rest of packet
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

		// Parse
		parse(&info, packet)
	}

	// On disconnet
	svr_notice_all(info.name + " disconnected")
	delete(clients, info.name)
}

// Parse incoming packet
func parse(info *ClientInfo, packet []byte) {
	// fmt.Printf("rx: ")
	// for i := 0; i < len(packet); i++ {
	// 	fmt.Printf("%02x ", packet[i])
	// }
	// fmt.Printf("\n")

	cmd := packet[0]
	switch {
	case cmd == CMD_MSGALL:
		cmd_msgall(info, packet[1:])
	case cmd == CMD_MSGTO:
		cmd_msgto(info, packet[1:])
	case cmd == CMD_IDENT:
		cmd_ident(info, packet[1:])
		fmt.Printf("user %s identified\n", info.name)
	case cmd == CMD_WHO:
		cmd_who(info)
	default:
	}
}

// Helper function to set common packet fields
func packetize(packet_type byte, payload []byte) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{ HEADER_BYTE })
	binary.Write(&buf, binary.BigEndian, uint32(len(payload)+1))
	buf.Write([]byte{ packet_type })
	buf.Write(payload)

//	var pkt []byte = buf.Bytes()
//	fmt.Printf("tx: ")
//	for i := 5; i < len(pkt); i++ {
//		fmt.Printf("%02x ", pkt[i])
//	}
//	fmt.Printf("\n")
	return buf.Bytes()
}

func svr_notice(c net.Conn, msg string) (int, error) {
	return c.Write(packetize(byte(SVR_NOTICE), []byte(msg)))
}

func svr_notice_all(msg string) (int, error) {
	return clients.Write(packetize(byte(SVR_NOTICE), []byte(msg)))
}

func cmd_msgall(info *ClientInfo, packet []byte) (int, error) {
	if info.name == "" {
		svr_notice(info.conn, "please identify yourself")
		return -1, nil
	}

	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint16(len(info.name)))
	buf.Write([]byte(info.name))
	buf.Write(packet)
	return clients.Write(packetize(SVR_MSG, buf.Bytes()))
}

func cmd_msgto(info *ClientInfo, packet []byte) (int, error) {
	if info.name == "" {
		svr_notice(info.conn, "please identify yourself")
		return -1, nil
	}

	targetlen := int(binary.BigEndian.Uint16(packet[0:2]))
	target := string(packet[2:2+targetlen])
	data := packet[2+targetlen:]

	c, present := clients[target]
	if !present {
		svr_notice(info.conn, fmt.Sprintf("unknown recipient %s", target))
		return -1, nil
	}

	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint16(len(info.name)))
	buf.Write([]byte(info.name))
	buf.Write(data)
	return c.Write(packetize(byte(SVR_MSG), buf.Bytes()))
}

func cmd_ident(info *ClientInfo, packet []byte) {
	name := string(packet)

	if len(name) > MAX_NAME_LENGTH {
		svr_notice(info.conn, "invalid name")
		return
	}

	if !clients.Add(name, info.conn) {
		svr_notice(info.conn, name + " is already in use")
		return
	}

	svr_notice_all(name + " connected")
	info.name = name
}

func cmd_who(info *ClientInfo) {
	if info.name == "" {
		svr_notice(info.conn, "please identify yourself")
		return
	} else {
	        msg := fmt.Sprintf("Who (%v users):\n", len(clients))
		for key, _ := range clients {
		         msg += fmt.Sprintf("  %v\n", key)
		}
		svr_notice(info.conn, msg)
        }
}

func main() {
	var (
		port int
		help bool
	)
	flag.IntVar(&port, "port", 6150, "Port to listen on")
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
