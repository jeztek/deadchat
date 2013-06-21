#!/usr/bin/env python

import urwid
import urwid.curses_display

class Client():
    def __init__(self):

        self.chatlog_init = map(lambda x: urwid.Text(str(x)), range(500))

        self.display_size = None	# cols, rows tuple

        # Generate user interface
        self.chatlog = urwid.SimpleListWalker(self.chatlog_init)
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
        

    def run(self):
        self.display_size = self.display.get_cols_rows()
        while True:
            self.draw_screen()
            keys = self.display.get_input()

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
                self.chatlog.append(urwid.Text(text))
                self.ui_listbox.set_focus(self.ui_listbox.get_focus()[1] + 1, coming_from='below')
                self.ui_input.set_edit_text("")

        elif key == "page down":
            self.ui_listbox.keypress(self.display_size, key)
        elif key == "page up":
            self.ui_listbox.keypress(self.display_size, key)
            
        else:
            self.ui_frame.keypress(self.display_size, key)


    def draw_screen(self):
        canvas = self.ui_frame.render(self.display_size, focus=True)
        self.display.draw_screen(self.display_size, canvas)


    def get_chatlog(self):
        return self.chatlog


def main():
    Client().run()

    
if __name__ == "__main__":
    main()
    
