package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
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

var clients clientMap

func init() {
	clients = make(clientMap)
}

func client(c net.Conn) {
	defer c.Close()

	br := bufio.NewReader(c)
	name := ""

	for {
		// Read bytes from client
		buf, err := br.ReadBytes('\n')
		if err != nil {
			break
		}
		buf = bytes.Trim(buf, "\t\n\r\x00")
		if len(buf) == 0 {
			continue
		}

		// Decode command from client
		switch {
		case strings.Contains(string(buf), "VALIDATE_NICK"):
			if name == "" {
				name = strings.TrimPrefix(string(buf), "VALIDATE_NICK ")
				if clients.Add(name, c) {
//					fmt.Fprintf(clients, "%v connected", name)
					fmt.Printf("%v connected\n", name)
//					defer fmt.Fprintf(clients, "%v disconnected", name)
					defer fmt.Printf("%v disconnected\n", name)
					defer delete(clients, name)
				} else {
					fmt.Fprintf(c, "Nick already exists")
					return
				}
			} else {
				fmt.Fprintf(c, "Nick already set")
			}
		default:
			if name != "" {
				msg := "<" + name + "> " + strings.TrimPrefix(string(buf), "SEND_MSG ")
				fmt.Fprintf(clients, "%v", msg)
				fmt.Printf("%v\n", msg)
			} else {
				fmt.Fprintf(c, "Nick not set")
			}
		}
	}
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
