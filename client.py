#!/usr/bin/env python

"""
TODO:
* binary protocol
* crypto

"""

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


class Command():
    SEND_MSG, VALIDATE_NICK = range(2)

    def __init__(self, type, data=None):
        self.type = type
        self.data = data

    def serialize(self):
        if self.type == self.SEND_MSG:
#            return u"SEND_MSG " + base64.b64encode(self.data) + u"\n"
            return u"SEND_MSG " + self.data + u"\n"
        elif self.type == self.VALIDATE_NICK:
            ret = u"VALIDATE_NICK " + self.data + u"\n"
            return ret.encode('utf-8')

class Response():
    MSG, DISCONNECTED = range(2)

    def __init__(self, type, data=None):
        self.type = type
        self.data = data


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
                cmd = self.queue.get(True, 0.125)
                self.sock.sendall(cmd.serialize())
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
                        data = sock.recv(4096)
                    except socket.error:
                        continue
                    if not data:
                        self.queue.put(Response(Response.DISCONNECTED))
                        self.enable.clear()
                    else:
                        self.queue.put(Response(Response.MSG, data))
    def stop(self):
        self.enable.clear()
        threading.Thread.join(self)


class DeadChatClient():
    def __init__(self):

        self.nick = None
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
        

    def load_config(self):
        self.config.read("deadchat.cfg")
        if self.config.has_section("id"):
            try:
                self.id_private_key = nacl.public.PrivateKey(base64.b64decode(self.config.get("id", "id_private_key")))
                self.id_public_key = nacl.public.PublicKey(base64.b64decode(self.config.get("id", "id_public_key")))
                self.nick = self.config.get("id", "nick")
                self.chatlog_add("Nick set to " + self.nick)
            except:
                pass

        if self.config.has_section("room"):
            try:
                self.shared_key = base64.b64decode(self.config.get("room", "room_key"))
                self.secretbox = nacl.secret.SecretBox(self.shared_key)
            except:
                pass


    def cmd_createid(self, nick):
        self.nick = nick
        key = nacl.public.PrivateKey.generate()
        self.id_private_key = key
        self.id_public_key = key.public_key

        self.chatlog_add(u"Created identity " + self.nick)
        if not self.config.has_section("id"):
            self.config.add_section("id")
        self.config.set("id", "id_private_key", base64.b64encode(self.id_private_key.encode()))
        self.config.set("id", "id_public_key", base64.b64encode(self.id_public_key.encode()))
        self.config.set("id", "nick", self.nick)
        with open("deadchat.cfg", "wb") as configfile:
            self.config.write(configfile)

        
    def cmd_connect(self, host, port):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, port))

            self.tx_thread = TransmitThread(self.sock, self.txq)
            self.tx_thread.start()

            self.rx_thread = ReceiveThread(self.sock, self.rxq)
            self.rx_thread.start()

            self.connected = True
            self.chatlog_add(u"Connected to " + host)

            self.txq.put(Command(Command.VALIDATE_NICK, self.nick))

        except Exception as e:
            self.chatlog_add(u"Unable to connect to " + host + \
                             u" on port " + str(port))
        

    def cmd_disconnect(self):
        self.connected = False
        self.rx_thread.stop()
        self.tx_thread.stop()
        self.sock.close()
        self.chatlog_add(u"Disconnected from server")

    def run(self):
        self.display_size = self.display.get_cols_rows()
        self.display.set_input_timeouts(max_wait=0.125)

        self.config = ConfigParser.ConfigParser()
        self.load_config()

        while self.enable:
            try:
                rx = self.rxq.get(False)
                if rx.type == Response.MSG:
                    if self.secretbox:
                        data = rx.data.split(" ")
                        enc = base64.b64decode(data[1])
                        msg = self.secretbox.decrypt(enc[24:], enc[:24])
                        self.chatlog_add(data[0] + " " + msg)
                elif rx.type == Response.DISCONNECTED:
                    self.cmd_disconnect()
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
                if text == "/quit":
                    if self.connected:
                        self.cmd_disconnect()
                    self.enable = False
                elif string.find(text, "/createid") == 0:
                    idstr = text.split(" ")
                    if len(idstr) > 1:
                        self.cmd_createid(idstr[1])
                    else:
                        self.chatlog_add("Missing nick")
                elif string.find(text, "/connect") == 0:
                    if self.connected:
                        self.chatlog_add(u"Already connected")
                    else:
                        if self.nick:
                            self.cmd_connect("localhost", 4000)
                        else:
                            self.chatlog_add(u"Missing nick")
                elif string.find(text, "/disconnect") == 0:
                    if self.connected:
                        self.cmd_disconnect()
                    else:
                        self.chatlog_add(u"Not connected")
                elif string.find(text, "/genkey") == 0:
                    self.shared_key = nacl.utils.random(32)
                    self.secretbox = nacl.secret.SecretBox(self.shared_key)
                    if not self.config.has_section("room"):
                        self.config.add_section("room")
                    self.config.set("room", "room_key", base64.b64encode(self.shared_key))
                    with open("deadchat.cfg", "wb") as configfile:
                        self.config.write(configfile)
                    self.chatlog_add("Room key generated")
                else:
                    if self.connected:
                        if not self.secretbox:
                            self.chatlog_add(u"Missing room key")
                        else:
                            nonce = nacl.utils.random(24)
                            enc = self.secretbox.encrypt(text.encode('utf-8'), nonce)
                            enc = base64.b64encode(enc)
                            self.txq.put(Command(Command.SEND_MSG, enc))
                    else:
                        self.chatlog_add(u"Not connected")

        elif key == "page down":
            self.ui_listbox.keypress(self.display_size, key)
        elif key == "page up":
            self.ui_listbox.keypress(self.display_size, key)
            
        else:
            self.ui_frame.keypress(self.display_size, key)


    def draw_screen(self):
        canvas = self.ui_frame.render(self.display_size, focus=True)
        self.display.draw_screen(self.display_size, canvas)


    def chatlog_add(self, text):
        self.chatlog.append(urwid.Text(text))
        self.ui_listbox.set_focus(self.ui_listbox.get_focus()[1] + 1, \
                                  coming_from='below')
        


def main():
    DeadChatClient().run()
    
if __name__ == "__main__":
    main()
    
