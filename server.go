package main

import (
	"bufio"
	"bytes"
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
	for k := range cm {
		if name == k {
			return false
		}
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
	fmt.Fprintf(c, "Please enter your name: ")
	buf, err := br.ReadBytes('\n')
	if err != nil {
		error_(err, -1)
		return
	}

	name := string(bytes.Trim(buf, "\t\n\r\x00"))
	if name == "" {
		fmt.Fprintf(c, "%v is invalid\n", name)
	}

	if !clients.Add(name, c) {
		fmt.Fprintf(c, "%v is not available\n", name)
		return
	}

	fmt.Fprintf(clients, "%v connected\n", name)
	defer fmt.Fprintf(clients, "%v disconnected\n", name)
	defer delete(clients, name)

	for {
		buf, err = br.ReadBytes('\n')
		if err != nil {
			break
		}
		buf = bytes.Trim(buf, "\t\n\r\x00")
		if len(buf) == 0 {
			continue
		}

		switch {
		default:
			buf = append([]byte("<"+name+"> "), buf...)
		}

		fmt.Fprintf(clients, "%v\n", string(buf))
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
