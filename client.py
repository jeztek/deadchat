#!/usr/bin/env python

"""
TODO:
* binary protocol
* crypto

"""

import sys
import logging
import socket
import select
import string
import threading
import Queue
import urwid
import urwid.curses_display

logging.basicConfig(filename="deadchat.log", level=logging.DEBUG)


class Command():
    SEND_MSG, VALIDATE_NICK = range(2)

    def __init__(self, type, data=None):
        self.type = type
        self.data = data

    def serialize(self):
        if self.type == self.SEND_MSG:
            ret = u"SEND_MSG " + self.data + u"\n"
            return ret.encode('utf-8')
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
        

    def cmd_connect(self, nick, host, port):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, port))

            self.tx_thread = TransmitThread(self.sock, self.txq)
            self.tx_thread.start()

            self.rx_thread = ReceiveThread(self.sock, self.rxq)
            self.rx_thread.start()

            self.connected = True
            self.chatlog_add(u"Connected to " + host)

            self.nick = nick
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
        while self.enable:
            try:
                rx = self.rxq.get(False)
                if rx.type == Response.MSG:
                    self.chatlog_add(rx.data)
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
                elif string.find(text, "/connect") == 0:
                    if self.connected:
                        self.chatlog_add(u"Already connected")
                    else:
                        connstr = text.split(" ")
                        if len(connstr) > 1:
                            nick = connstr[1]
                            self.cmd_connect(nick, "localhost", 4000)
                        else:
                            self.chatlog_add(u"Missing nick")
                elif string.find(text, "/disconnect") == 0:
                    if self.connected:
                        self.cmd_disconnect()
                    else:
                        self.chatlog_add(u"Not connected")
                else:
                    if self.connected:
                        self.txq.put(Command(Command.SEND_MSG, text))
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
    
