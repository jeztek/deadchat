#!/usr/bin/env python

# TODO:
# SSL connection to server
# disallow unicode names

from collections import deque

import sys
import base64
import logging
import socket
import select
import string
import struct
import threading
import Queue
import urwid
import urwid.curses_display
import nacl.utils
import nacl.public
import nacl.secret
import nacl.exceptions
import ConfigParser

logging.basicConfig(filename="deadchat.log", level=logging.DEBUG)

# Packet
# [header] [packet len except header (4)] [type (1)] [payload]
class Command():
    CMD_MSGALL, CMD_MSGTO, CMD_IDENT, CMD_WHO = range(4)

    MSG_REQ_SHAREKEY, MSG_SEND_SHAREKEY, MSG_ENC_SHAREKEY, \
    MSG_REQ_PUBKEY, MSG_SEND_PUBKEY, MSG_ENC_PUBKEY = range(6)

    def __init__(self, txq):
        self.queue = txq

    def packetize(self, command, payload=""):
        pktlen = len(payload) + 1
        return struct.pack("!cIB", '\xde', pktlen, command) + payload

    def msg_req_sharekey(self):
        payload = struct.pack("!B", Command.MSG_REQ_SHAREKEY)
        packet = self.packetize(Command.CMD_MSGALL, payload)
        self.queue.put(packet)

    def msg_enc_sharekey(self, data):
        payload = struct.pack("!B", Command.MSG_ENC_SHAREKEY) + data
        packet = self.packetize(Command.CMD_MSGALL, payload)
        self.queue.put(packet)

    def msg_send_sharekey(self, recipient, data):
        payload = struct.pack("!H", len(recipient))
        payload += recipient.encode('utf-8')
        payload += struct.pack("!B", Command.MSG_SEND_SHAREKEY)
        payload += data
        packet = self.packetize(Command.CMD_MSGTO, payload)
        self.queue.put(packet)

    def msg_req_pubkey(self, recipient, mykey):
        payload = struct.pack("!H", len(recipient))
        payload += recipient.encode('utf-8')
        payload += struct.pack("!B", Command.MSG_REQ_PUBKEY)
        payload += mykey
        packet = self.packetize(Command.CMD_MSGTO, payload)
        self.queue.put(packet)

    def msg_send_pubkey(self, recipient, data):
        payload = struct.pack("!H", len(recipient))
        payload += recipient.encode('utf-8')
        payload += struct.pack("!B", Command.MSG_SEND_PUBKEY)
        payload += data
        packet = self.packetize(Command.CMD_MSGTO, payload)
        self.queue.put(packet)

    def msg_enc_pubkey(self, recipient, data):
        payload = struct.pack("!H", len(recipient))
        payload += recipient.encode('utf-8')
        payload += struct.pack("!B", Command.MSG_ENC_PUBKEY)
        payload += data
        packet = self.packetize(Command.CMD_MSGTO, payload)
        self.queue.put(packet)

    def ident(self, name):
        packet = self.packetize(Command.CMD_IDENT, name.encode('utf-8'))
        self.queue.put(packet)

    def who(self):
        packet = self.packetize(Command.CMD_WHO)
        self.queue.put(packet)


class Response():
    SVR_NOTICE, SVR_MSG, DISCONNECTED = range(4, 7)

    def __init__(self, rtype):
        self.type = rtype


class TransmitThread(threading.Thread):
    def __init__(self, sock, queue):
        super(TransmitThread, self).__init__()
        self.sock = sock
        self.queue = queue
        self.enable = threading.Event()
        self.enable.set()

    def send_packet(self, packet):
        sent_bytes = 0
        pktlen = len(packet)
        while sent_bytes < pktlen:
            sent_bytes += self.sock.send(packet[sent_bytes:])
        return sent_bytes

    def run(self):
        while self.enable.is_set():
            try:
                packet = self.queue.get(True, 0.125)
                self.send_packet(packet)
            except Queue.Empty:
                continue

    def stop(self):
        self.enable.clear()
        threading.Thread.join(self)


class ReceiveThread(threading.Thread):
    def __init__(self, sock, queue):
        super(ReceiveThread, self).__init__()
        self.sock = sock
        self.queue = queue
        self.enable = threading.Event()
        self.enable.set()

    def get_packet(self, block=False):
        r = None
        if block:
            r, w, e = select.select([self.sock], [], [])
        else:
            r, w, e = select.select([self.sock], [], [], 0.125)
        for sock in r:
            if sock == self.sock:
                try:
                    read_bytes = 0
                    packet = ""
                    have_pktlen = False
                    # Receive data until we have length field from packet
                    while not have_pktlen:
                        tmp = sock.recv(4096)
                        if not tmp:
                            self.queue.put(Response(Response.DISCONNECTED))
                            self.enable.clear()
                            return
                        else:
                            packet += tmp
                            read_bytes += len(tmp)
                            header_index = tmp.find('\xde')
                            if header_index + 4 <= read_bytes:
                                have_pktlen = True

                    # Drop bytes before header
                    packet = packet[header_index:]
                    pktlen = struct.unpack("!I", packet[1:5])[0]
                    read_bytes = len(packet) - 1
                    while read_bytes < pktlen:
                        tmp = sock.recv(4096)
                        if not tmp:
                            self.queue.put(Response(Response.DISCONNECTED))
                            self.enable.clear()
                            return
                        else:
                            packet.append(tmp)
                            read_bytes += len(tmp)
                    return packet
                except socket.error:
                    return None
        return None

    def run(self):
        while self.enable.is_set():
            packet = self.get_packet()
            if packet:
                self.queue.put(packet)

    def stop(self):
        self.enable.clear()
        threading.Thread.join(self)


class DeadChatClient():
    MAX_NAME_LENGTH = 65535

    def __init__(self):

        self.name = None
        self.id_public_key = None
        self.id_private_key = None
        
        self.shared_key = None
        self.secretbox = None
        self.boxes = {}
        
        self.sock = None
        self.connected = False
        
        self.txq = Queue.Queue()
        self.rxq = Queue.Queue()

        self.tx_thread = None
        self.rx_thread = None

        self.send_cmd = Command(self.txq)

        self.enable = True
        self.display_size = None	# cols, rows tuple

        self.input_history = deque(maxlen=50)
        self.input_index = -1
        self.input_stash = ""
        
        # Generate user interface
        self.chatlog = urwid.SimpleListWalker([])
        self.ui_listbox = urwid.ListBox(self.chatlog)
        self.ui_listbox.set_focus(len(self.chatlog)-1)
        self.ui_status = urwid.Text(" deadchat")
        # Use unicode for parameters here otherwise urwid won't
        # accept unicode user input
        self.ui_input = urwid.Edit(u">> ")
        ui_header = urwid.AttrMap(urwid.Text(""), 'header')
        ui_footer = urwid.Pile([
            urwid.AttrMap(self.ui_status, 'status'),
            self.ui_input,
        ], focus_item=self.ui_input)
        self.ui_frame = urwid.Frame(self.ui_listbox, \
                                    header = ui_header, \
                                    footer = ui_footer, \
                                    focus_part = "footer")

        self.display = urwid.curses_display.Screen()
        self.display.register_palette([
            ('header', 'black', 'dark cyan', 'standout'),
            ('status', 'black', 'dark cyan', 'standout')
        ])

        # Run main loop
        try:
            self.display.run_wrapper(self.run)
        except KeyboardInterrupt:
            if self.connected:
                self.user_disconnect()
            if self.tx_thread:
                self.tx_thread.stop()
            if self.rx_thread:
                self.rx_thread.stop()
            self.enable = False
            sys.exit()


    def run(self):
        self.display_size = self.display.get_cols_rows()
        self.display.set_input_timeouts(max_wait=0.125)

        self.config = ConfigParser.ConfigParser()
        self.load_config()

        while self.enable:
            try:
                packet = self.rxq.get(False)
                self.parse_rx(packet)
            except Queue.Empty:
                pass

            self.draw_screen()
            keys = self.display.get_input()

            for key in keys:
                if key == "window resize":
                    self.display_size = self.display.get_cols_rows()
                    continue
                else:
                    self.keypress(key)


    def keypress(self, key):
        input = self.ui_input

        if key == "enter":
            text = input.get_edit_text()
            if text != "":
                self.input_history.appendleft(text)
                self.input_index = -1
                self.input_stash = ""
                self.ui_input.set_edit_text("")
                self.parse_user_input(text)
        elif key == "up":
            if len(self.input_history) > 0:
                if self.input_index < 0:
                    self.input_stash = input.get_edit_text()
                self.input_index = min(self.input_index + 1, \
                                       len(self.input_history) - 1)
                input.set_edit_text(self.input_history[self.input_index])
                input.set_edit_pos(len(input.get_edit_text()))
        elif key == "down":
            if len(self.input_history) > 0:
                if self.input_index == -1:
                    pass
                elif self.input_index == 0:
                    self.input_index = -1
                    input.set_edit_text(self.input_stash)
                    input.set_edit_pos(len(input.get_edit_text()))
                else:
                    self.input_index = max(self.input_index - 1, 0)
                    input.set_edit_text(self.input_history[self.input_index])
                    input.set_edit_pos(len(input.get_edit_text()))
        elif key == "ctrl a":
            input.set_edit_pos(0)
        elif key == "ctrl b":
            input.set_edit_pos(input.edit_pos - 1)
        elif key == "ctrl d":
            text = input.get_edit_text()
            input.set_edit_text(text[0:input.edit_pos] + \
                                text[input.edit_pos + 1:])
        elif key == "ctrl e":
            input.set_edit_pos(len(input.get_edit_text()))
        elif key == "ctrl f":
            input.set_edit_pos(input.edit_pos + 1)
        elif key == "ctrl k":
            input.set_edit_text(input.get_edit_text()[0:input.edit_pos])
        elif key == "page down":
            self.ui_listbox.keypress(self.display_size, key)
        elif key == "page up":
            self.ui_listbox.keypress(self.display_size, key)
        else:
            self.ui_frame.keypress(self.display_size, key)


    def draw_screen(self):
        canvas = self.ui_frame.render(self.display_size, focus=True)
        self.display.draw_screen(self.display_size, canvas)


    def chatlog_print(self, text):
        self.chatlog.append(urwid.Text(text))
        self.ui_listbox.set_focus(self.ui_listbox.get_focus()[1] + 1, \
                                  coming_from='below')


    def parse_rx(self, rx):
        if isinstance(rx, Response):
            # DISCONNECTED
            if rx.type == Response.DISCONNECTED:
                self.user_disconnect()
        else:
            rxtype = struct.unpack("!B", rx[5])[0]

            # SVR_NOTICE
            if rxtype == Response.SVR_NOTICE:
                msg = rx[6:]
                self.chatlog_print(msg)

            # SVR_MSG
            elif rxtype == Response.SVR_MSG:
                namelen = struct.unpack("!H", rx[6:8])[0]
                name = rx[8:8+namelen]
                msgtype = struct.unpack("!B", rx[8+namelen])[0]

                if msgtype == Command.MSG_REQ_SHAREKEY:
                    self.svr_msg_request_sharekey(name)
                elif msgtype == Command.MSG_SEND_SHAREKEY:
                    data = rx[8+namelen+1:]
                    self.svr_msg_send_sharekey(name, data)
                elif msgtype == Command.MSG_ENC_SHAREKEY:
                    data = rx[8+namelen+1:]
                    self.svr_msg_encrypted_sharekey(name, data)
                elif msgtype == Command.MSG_REQ_PUBKEY:
                    data = rx[8+namelen+1:]
                    self.svr_msg_request_pubkey(name, data)
                elif msgtype == Command.MSG_SEND_PUBKEY:
                    data = rx[8+namelen+1:]
                    self.svr_msg_send_pubkey(name, data)
                elif msgtype == Command.MSG_ENC_PUBKEY:
                    data = rx[8+namelen+1:]
                    self.svr_msg_encrypted_pubkey(name, data)


    def parse_user_input(self, text):
        if string.find(text, "/help") == 0:
            helpstr = \
"""
/quit                   Exit program
/connect <host> <port>  Connect to server
/disconnect             Disconnect from server
/who                    List users in room

/createid <name>        Create identity and associated keys
/idexch <name>          Request id key exchange

/genroomkey             Generate a secret key for the room
/reqroomkey             Request the secret key from the room
/sendroomkey <name>     Send secret key for the room

/msg <name> <msg>       Send private message
"""
            self.chatlog_print(helpstr)

        # /quit
        elif string.find(text, "/quit") == 0:
            if self.connected:
                self.user_disconnect()
            self.enable = False

        # /createid <name>
        elif string.find(text, "/createid") == 0:
            idstr = text.split(" ")
            if len(idstr) > 1:
                self.user_createid(idstr[1])
            else:
                self.chatlog_print("Missing name")

        # /connect
        elif string.find(text, "/connect") == 0:
            if self.connected:
                self.chatlog_print("Already connected")
                return

            if not self.name:
                self.chatlog_print("Missing name, set using /createid")
                return
            
            host = None
            port = None
            connstr = text.split(" ")
            if len(connstr) == 1:
                self.config.read("deadchat.cfg")
                if self.config.has_section("server"):
                    host = self.config.get("server", "host")
                    port = int(self.config.get("server", "port"))
                    self.chatlog_print(host + " " + str(port))
            elif len(connstr) == 2:
                host = connstr[1]
                port = 6150
            elif len(connstr) >= 3:
                try:
                    host = connstr[1]
                    port = int(connstr[2])
                except:
                    self.chatlog_print("Invalid host or port")
                    return
            else:
                self.chatlog_print("Missing host and/or port")
                return
            
            self.user_connect(host, port)
            self.send_cmd.ident(self.name)

        # /disconnect
        elif string.find(text, "/disconnect") == 0:
            if self.connected:
                self.user_disconnect()
            else:
                self.chatlog_print("Not connected")

        # /who
        elif string.find(text, "/who") == 0:
            if self.connected:
                self.send_cmd.who()
            else:
                self.chatlog_print("Not connected")

        # /genroomkey
        elif string.find(text, "/genroomkey") == 0:
            self.user_genroomkey()

        # /reqroomkey
        elif string.find(text, "/reqroomkey") == 0:
            if self.connected:
                self.send_cmd.msg_req_sharekey()
            else:
                self.chatlog_print("Not connected")

        # /sendroomkey <name>
        elif string.find(text, "/sendroomkey") == 0:
            sendroomkeystr = text.split(" ")
            if len(sendroomkeystr) > 1:
                if self.connected:
                    self.user_sendroomkey(sendroomkeystr[1])
                else:
                    self.chatlog_print("Not connected")
            else:
                self.chatlog_print("Missing name")

        # /idexch <name>
        elif string.find(text, "/idexch") == 0:
            idexchstr = text.split(" ")
            if len(idexchstr) > 1:
                if self.connected:
                    self.user_idexch(idexchstr[1])
                else:
                    self.chatlog_print("Not connected")
            else:
                self.chatlog_print("Missing name")

        # /msg <name> <msg>
        elif string.find(text, "/msg") == 0:
            msgstr = text.split(" ", 2)
            if len(msgstr) > 1:
                if self.connected:
                    if len(msgstr) >= 3:
                        msg = msgstr[2]
                    else:
                        msg = ""
                    self.user_msg(msgstr[1], msg)
                else:
                    self.chatlog_print("Not connected")
            else:
                self.chatlog_print("Missing name")

        # not a command
        else:
            if self.connected:
                if not self.secretbox:
                    self.chatlog_print("Missing room key")
                else:
                    # TODO: ensure nonces are never repeated
                    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
                    enc = self.secretbox.encrypt(text.encode('utf-8'), nonce)
                    self.send_cmd.msg_enc_sharekey(enc)
            else:
                self.chatlog_print("Not connected")

    
    def load_config(self):
        self.config.read("deadchat.cfg")
        if self.config.has_section("id"):
            try:
                self.id_private_key = nacl.public.PrivateKey(base64.b64decode(self.config.get("id", "id_private_key")))
                self.id_public_key = nacl.public.PublicKey(base64.b64decode(self.config.get("id", "id_public_key")))
                self.name = self.config.get("id", "name")
                self.ui_status.set_text("deadchat - " + self.name)
                self.chatlog_print("Name set to " + self.name)
            except:
                pass

        if self.config.has_section("room"):
            try:
                self.shared_key = base64.b64decode(self.config.get("room", "room_key"))
                self.secretbox = nacl.secret.SecretBox(self.shared_key)
            except:
                pass


    def user_createid(self, name):
        if len(name) > DeadChatClient.MAX_NAME_LENGTH:
            self.chatlog_print("That name is too long")
            return

        self.name = name
        key = nacl.public.PrivateKey.generate()
        self.id_private_key = key
        self.id_public_key = key.public_key

        self.ui_status.set_text("deadchat - " + self.name)
        self.chatlog_print("Created identity " + self.name)
        if not self.config.has_section("id"):
            self.config.add_section("id")
        self.config.set("id", "id_private_key", \
                        base64.b64encode(self.id_private_key.encode()))
        self.config.set("id", "id_public_key", \
                        base64.b64encode(self.id_public_key.encode()))
        self.config.set("id", "name", self.name.encode('utf-8'))
        with open("deadchat.cfg", "wb") as configfile:
            self.config.write(configfile)

        
    def user_connect(self, host, port):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, port))

            self.tx_thread = TransmitThread(self.sock, self.txq)
            self.tx_thread.start()

            self.rx_thread = ReceiveThread(self.sock, self.rxq)
            self.rx_thread.start()

            self.connected = True
            self.chatlog_print("Connected to " + host)

            self.config.read("deadchat.cfg")
            if not self.config.has_section("server"):
                self.config.add_section("server")
            self.config.set("server", "host", host)
            self.config.set("server", "port", port)
            with open("deadchat.cfg", "wb") as configfile:
                self.config.write(configfile)

        except Exception as e:
            self.chatlog_print("Unable to connect to " + host + \
                               " on port " + str(port))
        

    def user_disconnect(self):
        self.connected = False
        self.rx_thread.stop()
        self.tx_thread.stop()
        self.sock.close()
        self.chatlog_print("Disconnected from server")

        
    def user_genroomkey(self):
        self.shared_key = nacl.utils.random(nacl.SecretBox.KEY_SIZE)
        self.secretbox = nacl.secret.SecretBox(self.shared_key)
        if not self.config.has_section("room"):
            self.config.add_section("room")
        self.config.set("room", "room_key", base64.b64encode(self.shared_key))
        with open("deadchat.cfg", "wb") as configfile:
            self.config.write(configfile)
        self.chatlog_print("Room key generated")


    def user_sendroomkey(self, name):
        if self.init_pubkey(name):
            # TODO: look into nonce prefix
            nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
            enc = self.boxes[name].encrypt(self.shared_key, nonce)
            self.send_cmd.msg_send_sharekey(name, enc)
            self.chatlog_print("Sent room key to " + name)
        else:
            self.chatlog_print("No key for " + name + ", run /idexch first")


    def user_idexch(self, name):
        key = self.id_public_key.encode()
        self.send_cmd.msg_req_pubkey(name, key)
        self.chatlog_print("Requested room key from " + name)


    def user_msg(self, name, msg):
        if self.init_pubkey(name):
            # TODO: look into nonce prefix
            nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
            enc = self.boxes[name].encrypt(msg.encode('utf-8'), nonce)
            self.send_cmd.msg_enc_pubkey(name, enc)
            self.chatlog_print("[%s => %s] %s" % (self.name, name, msg))
        else:
            self.chatlog_print("No key for " + name + ", run /idexch first")


    def init_pubkey(self, name):
        if self.boxes.has_key(name):
            return True

        self.config.read("deadchat.cfg")
        if self.config.has_section("keys"):
            try:
                b64key = self.config.get("keys", name)
                key = nacl.public.PublicKey(base64.b64decode(b64key))
                self.boxes[name] = nacl.public.Box(self.id_private_key, key)
                return True
            except:
                pass
        return False


    def svr_msg_request_sharekey(self, sender):
        self.chatlog_print(sender + " requests the room key")


    def svr_msg_send_sharekey(self, sender, data):
        if self.init_pubkey(sender):
            nonce = data[0:nacl.public.Box.NONCE_SIZE]
            enc = data[nacl.public.Box.NONCE_SIZE:]
            self.shared_key = self.boxes[sender].decrypt(enc, nonce)
            self.secretbox = nacl.secret.SecretBox(self.shared_key)
            if not self.config.has_section("room"):
                self.config.add_section("room")
            self.config.set("room", "room_key", base64.b64encode(self.shared_key))
            with open("deadchat.cfg", "wb") as configfile:
                self.config.write(configfile)
            self.chatlog_print(sender + " has sent you the room key")
        else:
            self.chatlog_print("Received room key from " + sender + \
                               " but unable to decrypt, run /idexch")


    def svr_msg_encrypted_sharekey(self, sender, data):
        nonce = data[0:nacl.secret.SecretBox.NONCE_SIZE]
        enc = data[nacl.secret.SecretBox.NONCE_SIZE:]
        if self.secretbox:
            try:
                msg = self.secretbox.decrypt(enc, nonce)
                self.chatlog_print("<" + sender + "> " + msg)
                return
            except nacl.exceptions.CryptoError:
                pass
        self.chatlog_print("<" + sender + "> ( encrypted )")


    # Received request for my public key
    def svr_msg_request_pubkey(self, sender, data):
        # store key from sender
        if not self.config.has_section("keys"):
            self.config.add_section("keys")
        self.config.set("keys", sender, base64.b64encode(data))
        with open("deadchat.cfg", "wb") as configfile:
            self.config.write(configfile)

        # TODO: handle if public_key not set
        key = self.id_public_key.encode()
        self.send_cmd.msg_send_pubkey(sender, key)
        self.chatlog_print("Received id key request from " + sender)


    # Received requested public key from sender
    # TODO: sanitize data
    def svr_msg_send_pubkey(self, sender, data):
        # save key to config file
        if not self.config.has_section("keys"):
            self.config.add_section("keys")
        self.config.set("keys", sender, base64.b64encode(data))
        with open("deadchat.cfg", "wb") as configfile:
            self.config.write(configfile)
        self.chatlog_print("id key exchange with " + sender + " complete")


    def svr_msg_encrypted_pubkey(self, sender, data):
        if self.init_pubkey(sender):
            nonce = data[0:nacl.public.Box.NONCE_SIZE]
            enc = data[nacl.public.Box.NONCE_SIZE:]
            msg = self.boxes[sender].decrypt(enc, nonce)
            self.chatlog_print("[%s => %s] %s" % (sender, self.name, msg))
        else:
            self.chatlog_print("[%s => %s] ( unable to decrypt, run /idexch )" % (sender, self.name))

        
def main():
    DeadChatClient().run()
    
if __name__ == "__main__":
    main()
    
