package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/nsf/termbox-go"
	"os"
//	"unicode/utf8"
//	"strconv"
)

type ChatLog []string



type DeadChatClient struct {
	ui_width int
	ui_height int
	ui_input bytes.Buffer
	chatlog ChatLog
}

var client DeadChatClient

func init() {
	err := termbox.Init()
	if err != nil {
		error_(err, -1)
	}
	defer termbox.Close()

	client.ui_width, client.ui_height = termbox.Size()
	client.chatlog = make([]string, client.ui_height)
}

func error_(err error, r int) {
	fmt.Printf("Error: %v\n", err)
	if r >= 0 {
		os.Exit(r)
	}
}

func ui_print(x, y int, msg string, fg, bg termbox.Attribute) {
	for _, c := range msg {
		termbox.SetCell(x, y, c, fg, bg)
		x += 1
	}
}

func ui_draw_banner(msg string) {
	for i := 0; i < client.ui_width; i++ {
			termbox.SetCell(i, client.ui_height-2, 0x2588, termbox.ColorCyan, termbox.ColorCyan)
	}
	ui_print(0, client.ui_height-2, msg, termbox.ColorBlack, termbox.ColorCyan)
}

func ui_draw() {
	ui_draw_banner("deadchat")
	ui_print(0, client.ui_height-1, ">> " + client.ui_input.String(), termbox.ColorWhite, termbox.ColorBlack)	
}

func ui_keypress(ev *termbox.Event) {
	switch ev.Key {
	case termbox.KeyBackspace, termbox.KeyBackspace2:
		len := client.ui_input.Len()
		if len > 0 {
			client.ui_input.Truncate(len-1)
		}
	case 10, 13:
		client.ui_input.Reset()
	default:
		client.ui_input.WriteRune(ev.Ch)
	}
}

func ui_loop() {
loop:
	for {
		termbox.Clear(termbox.ColorWhite, termbox.ColorBlack)
		ui_draw()
		termbox.Flush()
		switch ev := termbox.PollEvent(); ev.Type {
		case termbox.EventKey:
			if ev.Key == termbox.KeyCtrlC {
				break loop
			}
			ui_keypress(&ev)
		case termbox.EventResize:
			client.ui_width = ev.Width
			client.ui_height = ev.Height
		case termbox.EventError:
			error_(ev.Err, -1)
		}
	}
}

func main() {
	var (
		help bool
	)
	if help {
		flag.Usage()
		return
	}

	ui_loop()
}
