package main

import (
  "fmt"
  "encoding/binary"
  "bytes"
  "menteslibres.net/gosexy/redis" 
)


// === Server ===
// Packet format
// [header (1)] [packet type (1)] [packet length (4)] [payload (n)]

// RX: MSGALL
// [data (n)]
// TX: MSG
// [nicklen (4)] [sender nick (n)] [data (n)]

// RX: MSGTO
// [nicklen (4)] [target nick (n)] [data (n)]
// TX: MSG
// [nicklen (4)] [sender nick (n)] [data (n)]

// RX: IDENT
// [nick (n)]
// TX: IDENT
// [challenge] [public key]

// RX: AUTH
// [challenge response (n)]
// TX: AUTH_VALID
// TX: AUTH_INVALID

// RX: GETPK
// [nick (n)]
// TX: PK
// [key (n)]

// RX: WHO
// TX: WHO
// [numusers (4)] [[nicklen (4)] [nick (n)]]


// === Client ===
// TX: IDENT
// [nick (n)]
// RX: IDENT
// [challenge] [public key]

// TX: AUTH
// [challenge response (n)]
// RX: AUTH_VALID
// RX: AUTH_INVALID

// TX: MSGALL
// [nonce] [encrypted text]
// RX: MSG
// [nicklen (4)] [sender nick (n)] [nonce] [encrypted text]

// TX: REQKEY
// RX: MSG
// [nicklen (4)] [sender nick (n)] [encrypted key]
// TX: GETPK
// [nick (n)]
// RX: PK
// [key (n)]

// SENDKEY
// TX: GETPK
// [nick (n)]
// RX: PK
// [key (n)]]
// TX: MSGTO
// [nicklen (4)] [target nick (n)] [encrypted key]

// TX: WHO
// RX: WHO
// 
// TX: MSGTO

// TX: WHO
// RX: WHO

// TX: SENDKEY


// TX: REQKEY

// RX: REQKEY



//   MSG     [nonce] [encrypted msg]
//   REQKEY

//   SENDKEY [nicklen (4)] [nick (n)] [encrypted key]

// Comands received from client
const (
  MSGALL = iota  // broadcast
  MSGTO          // find target nick and send
  IDENT          // receive nick, respond with challenge and public key
  AUTH           // receive challenge response, validate
  GETPK          // respond with requested user's public key
  WHO            // get list of users
)

// Server responses
const (
  MSG = iota  // append nick and send
  IDENT       // send challenge + public key
  AUTH_VALID  
  AUTH_INVALID  
  PK
  WHO         // list of users
)

func main() {
  var client *redis.Client
  var err error
  client = redis.New()
  err = client.Connect("localhost", 6379)

  if err != nil {
    fmt.Printf("Connect failed: %s\n", err.Error())
    return 
  }

  nick := "こんにちは"
  client.HSet("userkeys", nick, "thisisakeyforanick")
  key, err := client.HGet("userkeys", nick)
  fmt.Printf("%s => %s\n", nick, key)

  var buf bytes.Buffer  
  var pktlen uint32 = 6	// header, type, packet len

  nickb := []byte(nick)
  nicklen := uint32(len(nickb))
  pktlen += nicklen + uint32(4) // nick + nicklen

  buf.Write([]byte{'\xde', 1}) // header
  binary.Write(&buf, binary.BigEndian, pktlen) // packet len
  binary.Write(&buf, binary.BigEndian, nicklen) // nick len
  buf.Write([]byte(nick)) // nick
  b := buf.Bytes()

  for i := 0; i < len(b); i++ {
    fmt.Printf("%02x ", b[i])
  }
  fmt.Printf("\n")

  pktlen = binary.BigEndian.Uint32(b[2:])
  nicklen = binary.BigEndian.Uint32(b[6:])
  fmt.Printf("%02x type %d, len %d, nicklen %d, nick %s\n", 
	     b[0], b[1], pktlen, nicklen, b[10:])
  client.Quit()

}
