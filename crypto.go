package main

import (
	"os"
	"fmt"
	"encoding/base64"
	"code.google.com/p/go.crypto/nacl/box"
)

func decrypt(priv_key, pub_key, nonce, cipher string) {
	fmt.Printf("decrypting...\n")
	
	private_key,_ := base64.StdEncoding.DecodeString(priv_key)
	public_key, _ := base64.StdEncoding.DecodeString(pub_key)
	enc_nonce, _  := base64.StdEncoding.DecodeString(nonce)
	enc_cipher,_  := base64.StdEncoding.DecodeString(cipher)

	var n [24]byte
	for i := 0; i < 24; i++ {
		n[i] = enc_nonce[i]
	}

	var prk [32]byte
	for i := 0; i < 32; i++ {
		prk[i] = private_key[i]
	}

	var puk [32]byte
	for i := 0; i < 32; i++ {
		puk[i] = public_key[i]
	}

	var msg []byte
	msg, ok := box.Open(msg[:0], enc_cipher, &n, &puk, &prk)
	if ok {
		fmt.Printf("%v\n", string(msg))
	} else {
		fmt.Printf("error\n")
	}

}

func main() {
	args := os.Args
	decrypt(args[1], args[2], args[3], args[4])
}
