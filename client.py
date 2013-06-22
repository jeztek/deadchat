#!/usr/bin/env python

import sys
import logging
import socket
import select
import threading
import Queue
import urwid
import urwid.curses_display

logging.basicConfig(filename="deadchat.log", level=logging.DEBUG)


class ReceiveThread(threading.Thread):
    def __init__(self, sock, queue):
        super(ReceiveThread, self).__init__()
        self.sock  = sock
        self.queue = queue
        self.enabled = threading.Event()
        self.enabled.set()

    def run(self):
        while self.enabled.is_set():
            r, w, e = select.select([self.sock], [], [], 0.125)
            for sock in r:
                if sock == self.sock:
                    try:
                        data = sock.recv(4096)
                    except socket.error:
                        continue
                    if not data:
                        # disconnected
                        self.queue.put("server disconnect")
                        self.enabled.clear()
                    else:
                        self.queue.put(data)

    def stop(self):
        self.enabled.clear()
        threading.Thread.join(self)


class TransmitThread(threading.Thread):
    def __init__(self, sock, queue):
        super(TransmitThread, self).__init__()
        self.sock = sock
        self.queue = queue
        self.enabled = threading.Event()
        self.enabled.set()

    def run(self):
        while self.enabled.is_set():
            try:
                data = self.queue.get(True, 0.125)
                logging.debug("tx thread: " + data)
                self.sock.sendall(data + '\n')
            except Queue.Empty:
                continue

    def stop(self):
        self.enabled.clear()
        threading.Thread.join(self)


class Client():
    def __init__(self, sock):

        self.txq = Queue.Queue()
        self.rxq = Queue.Queue()

        tx = TransmitThread(sock, self.txq)
        rx = ReceiveThread(sock, self.rxq)

        tx.start()
        rx.start()

        self.txq.put("Eric\n")

        self.enabled = True
        self.display_size = None	# cols, rows tuple

        # Generate user interface
        self.chatlog = urwid.SimpleListWalker([])
        self.ui_listbox = urwid.ListBox(self.chatlog)
        self.ui_listbox.set_focus(len(self.chatlog)-1)
        self.ui_status = urwid.Text(" #chatroom")
        self.ui_input = urwid.Edit(">> ")
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
        rx.stop()
        tx.stop()
        sock.close()
        

    def run(self):
        self.display_size = self.display.get_cols_rows()
        self.display.set_input_timeouts(max_wait=0.125)
        while self.enabled:
            try:
                text = self.rxq.get(False)
                self.chatlog_add(text)
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
                self.txq.put(text)
            if text == "/quit":
                self.enabled = False

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
    if len(sys.argv) < 3:
        print "Usage:", sys.argv[0], "hostname port"
        sys.exit()

    host = sys.argv[1]
    port = int(sys.argv[2])

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
    except:
        print "Unable to connect to", host
        sys.exit()

    Client(sock).run()

    
if __name__ == "__main__":
    main()
    
