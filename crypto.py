#!/usr/bin/env python
# -*- coding: utf-8 -*-

import nacl.utils
import nacl.public
import nacl.secret
import base64

private_key_client = nacl.public.PrivateKey.generate()
public_key_client = private_key_client.public_key

private_key_server = nacl.public.PrivateKey.generate()
public_key_server = private_key_server.public_key

box = nacl.public.Box(private_key_client, public_key_server)
enc = box.encrypt(u"こんにちはお元気ですか？".encode('utf-8'), nacl.utils.random(24))

print base64.b64encode(private_key_server.encode())
print base64.b64encode(public_key_client.encode())
print base64.b64encode(enc.nonce)
print base64.b64encode(enc.ciphertext)

shared_key = nacl.utils.random(32)
secbox = nacl.secret.SecretBox(shared_key)

nonce = b"n" + nacl.utils.random(23)
enc = secbox.encrypt(u"こんにちはお元気ですか？".encode('utf-8'), nonce)

dec = secbox.decrypt(enc.ciphertext, enc.nonce)
print str(dec)

# print base64.b64encode(private_key.encode())
# print base64.b64encode(public_key.encode())
# print base64.b64encode(enc.nonce)
# print base64.b64encode(enc.ciphertext)
# print box.decrypt(enc.ciphertext, enc.nonce)

"""
Need:
* secret key exchange
* don't trust server with message content
* end points are trusted
* prevent eavesdropping
* server manages user identities

* all users make account on server (public key associated with nick)
* clients all have server public key

* user: connect, send nick
* server: send challenge
* user: send response
* server: verify response -> validated user

* user 1: room is empty, set room key

* user 2: request room key
* user 1: request user 2 public key from server
          send room key to user 2 encrypted with user 2 public key,
          signed with user 1 private key
          
* user 2: request user 1 public key from server
          decrypt room key using user 2 private key, verify with user 1
          public key
* user 2: transmit using room key

client commands:
/createid <nick> - generate key pair and set nick, store in file
/connect - connect to server
/disconnect - disconnect from server
/genkey - set room key and store in file
/requestkey - request room key
/sendkey <nick> - send key to user

"""
