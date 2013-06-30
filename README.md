deadchat
========

### About

*deadchat* is a cryptographically secure single-room chat server and client.  It features end-to-end encryption where messages are encrypted and decrypted at the end points such that malicious machines on the network cannot eavesdrop on the conversation, including the chat server.


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
