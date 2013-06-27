#!/usr/bin/env python

import sys
import base64
import logging
import socket
import select
import string
import threading
import Queue
import urwid
import urwid.curses_display
import nacl.utils
import nacl.public
import nacl.secret
import ConfigParser

logging.basicConfig(filename="deadchat.log", level=logging.DEBUG)

# Packet
# [header] [packet len except header (4)] [type (1)] [packet data]
class Command():
    CMD_MSGALL, CMD_MSGTO, CMD_IDENT, CMD_AUTH, CMD_GETPK, CMD_WHO = range(6)

    def __init__(self, txq):
        self.queue = txq

    def packetize(self, command, payload):
        pktlen = len(payload) + 1
        return struct.pack("!cIB", '\xde', pktlen, command) + payload

    
    def msgall(self, data):
        packet = self.packetize(CMD_MSGALL, data)
        self.queue.put(packet)

    def ident(self, name):
        packet = self.packetize(CMD_IDENT, name.encode('utf-8'))
        self.queue.put(packet)


class Response():
    SVR_NOTICE, SVR_MSG, SVR_IDENT, SVR_AUTH_VALID, SVR_PK, SVR_WHO, DISCONNECTED = range(6, 13)

    def __init__(self, rtype):
        self.type = rtype


class TransmitThread(threading.Thread):
    def __init__(self, sock, queue):
        super(TransmitThread, self).__init__()
        self.sock = sock
        self.queue = queue
        self.enable = threading.Event()
        self.enable.set()

    def run(self):
        while self.enable.is_set():
            try:
                packet = self.queue.get(True, 0.125)
                sent_bytes = 0
                pktlen = len(packet)
                while sent_bytes < pktlen:
                    sent_bytes += self.sock.send(packet[sent_bytes:])
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

    def run(self):
        while self.enable.is_set():
            r, w, e = select.select([self.sock], [], [], 0.125)
            for sock in r:
                if sock == self.sock:
                    try:
                        read_bytes = 0
                        packet = []
                        have_pktlen = False
                        # Receive data until we have length field from packet
                        while not have_pktlen:
                            tmp = sock.recv(4096)
                            if not tmp:
                                self.queue.put(Response(Response.DISCONNECTED))
                                self.enable.clear()
                                break
                            else:
                                packet.append(tmp)
                                read_bytes += len(tmp)
                                header_index = tmp.find('\xde')
                                if header_index + 4 <= read_bytes:
                                    have_pktlen = True

                        # Drop bytes before header
                        packet = packet[header_index:]
                        pktlen = struct.unpack("!I", packet[1:4])

                        read_bytes = len(packet) - 1
                        while read_bytes < pktlen:
                            tmp = sock.recv(4096)
                            if not tmp:
                                self.queue.put(Response(Response.DISCONNECTED))
                                self.enable.clear()
                                break
                            else:
                                packet.append(tmp)
                                read_bytes += len(tmp)
                        self.queue.put(packet)
                    except socket.error:
                        continue

    def stop(self):
        self.enable.clear()
        threading.Thread.join(self)


class DeadChatClient():
    def __init__(self):

        self.name = None
        self.id_public_key = None
        self.id_private_key = None
        
        self.shared_key = None
        self.secretbox = None
        
        self.sock = None
        self.connected = False
        
        self.txq = Queue.Queue()
        self.rxq = Queue.Queue()

        self.tx_thread = None
        self.rx_thread = None

        self.send_cmd = Command(self.txq)

        self.enable = True
        self.display_size = None	# cols, rows tuple

        # Generate user interface
        self.chatlog = urwid.SimpleListWalker([])
        self.ui_listbox = urwid.ListBox(self.chatlog)
        self.ui_listbox.set_focus(len(self.chatlog)-1)
        self.ui_status = urwid.Text(u" deadchat")
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
        self.display.run_wrapper(self.run)
        

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
            try:
                keys = self.display.get_input()
            except KeyboardInterrupt:
                pass
            for key in keys:
                if key == "window resize":
                    self.display_size = self.display.get_cols_rows()
                    continue
                else:
                    self.keypress(key)


    def keypress(self, key):
        if key == "enter":
            text = self.ui_input.get_edit_text()
            if text != "":
                self.ui_input.set_edit_text("")
                self.parse_user_input(text)
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
        if type(rx) == Response:
            if rx.type == Response.DISCONNECTED:
                self.user_disconnect()
        else:
            svr_type = rx[5]
            if svr_type == Response.SVR_NOTICE:
                msg = rx[6:]
                self.chatlog_print(msg)
            elif svr_type == Response.SVR_MSG:
                if self.secretbox:
                    namelen = struct.unpack("!I", rx[6:7])
                    name = rx[8:8+namelen]
                    msg = self.secretbox.decrypt(rx[8+namelen+24:], rx[8+namelen:8+namelen+24])
                    self.chatlog_print("<" + name + "> " + msg)
            elif svr_type == Response.SVR_AUTH_VALID:
                self.chatlog_print("Identity confirmed")
                

    def parse_user_input(self, text):
        # /quit
        if string.find(text, "/quit") == 0:
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
                self.chatlog_print(u"Already connected")
            else:
                if self.name:
                    self.user_connect("localhost", 4000)
                else:
                    self.chatlog_print(u"Missing name, set using /createid")

        # /disconnect
        elif string.find(text, "/disconnect") == 0:
            if self.connected:
                self.user_disconnect()
            else:
                self.chatlog_print(u"Not connected")

        # /genkey
        elif string.find(text, "/genkey") == 0:
            self.usere_genkey()

        # msgall
        else:
            if self.connected:
                if not self.secretbox:
                    self.chatlog_print(u"Missing room key")
                else:
                    nonce = nacl.utils.random(24)
                    enc = self.secretbox.encrypt(self.data.encode('utf-8'), nonce)
                    self.send_cmd.msgall(enc)
            else:
                self.chatlog_print(u"Not connected")

    
    def load_config(self):
        self.config.read("deadchat.cfg")
        if self.config.has_section("id"):
            try:
                self.id_private_key = nacl.public.PrivateKey(base64.b64decode(self.config.get("id", "id_private_key")))
                self.id_public_key = nacl.public.PublicKey(base64.b64decode(self.config.get("id", "id_public_key")))
                self.name = self.config.get("id", "name")
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
        self.name = name
        key = nacl.public.PrivateKey.generate()
        self.id_private_key = key
        self.id_public_key = key.public_key

        self.chatlog_print(u"Created identity " + self.name)
        if not self.config.has_section("id"):
            self.config.add_section("id")
        self.config.set("id", "id_private_key", base64.b64encode(self.id_private_key.encode()))
        self.config.set("id", "id_public_key", base64.b64encode(self.id_public_key.encode()))
        self.config.set("id", "name", self.name)
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
            self.chatlog_print(u"Connected to " + host)

            self.send_cmd.ident(self.name)

        except Exception as e:
            self.chatlog_print(u"Unable to connect to " + host + \
                             u" on port " + str(port))
        

    def user_disconnect(self):
        self.connected = False
        self.rx_thread.stop()
        self.tx_thread.stop()
        self.sock.close()
        self.chatlog_print(u"Disconnected from server")


    def user_genkey(self):
        self.shared_key = nacl.utils.random(32)
        self.secretbox = nacl.secret.SecretBox(self.shared_key)
        if not self.config.has_section("room"):
            self.config.add_section("room")
        self.config.set("room", "room_key", base64.b64encode(self.shared_key))
        with open("deadchat.cfg", "wb") as configfile:
            self.config.write(configfile)
        self.chatlog_print("Room key generated")

        
def main():
    DeadChatClient().run()
    
if __name__ == "__main__":
    main()
    
