deadchat
========

### About

*deadchat* is a cryptographically secure single-room group chat server and client designed to enable a group of trusted friends to communicate with each other over an insecure channel without fear of eavesdropping.  

*deadchat* features end-to-end encryption where messages are encrypted and decrypted at the end points such that the server and malicious machines on the network cannot eavesdrop on the conversation.

It is assumed that a member of the trusted group will operate the server.

### DISCLAIMER

This work represents an endeavor to implement the functionality outlined above.  It is still a work in progress and is not recommended for use unless you intend to help make improvements.

### Usage

Run server.go on a server and connect to it with client.py.  The client supports the following commands:

```
/quit                   Exit program
/connect <host> <port>  Connect to server
/disconnect             Disconnect from server
/who                    List users in room

/createid <name>        Create identity and associated keys
/idexch <name>          Exchange id keys

/genroomkey             Generate a secret key for the room
/reqroomkey             Request the secret key from the room
/sendroomkey <name>     Send secret key for the room

/msg <name> <msg>       Send private message
```

### Todo

* Support SSL connections to server
* Disallow unicode usernames
* Implement client in Go
* Encrypt deadchat.cfg file

### Implementation

* *deadchat* is meant to run in a terminal (think IRC)
* Authenticated encryption is provided by [libsodium] (https://github.com/jedisct1/libsodium)
* *deadchat* uses public key cryptography for private messaging and room secret key exchange
* Group chat is encrypted using secret key cryptography
* Keys are stored in deadchat.cfg

### Client dependencies
* [urwid]      (http://excess.org/urwid)
* [libsodium]  (https://github.com/jedisct1/libsodium)
* [pynacl]     (https://github.com/dstufft/pynacl)

### Server dependencies
* go.crypto.nacl

```
go get code.google.com/p/go.crypto/nacl
go install code.google.com/p/go.crypto/nacl/secretbox
go install code.google.com/p/go.crypto/nacl/box
```
