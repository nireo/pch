package pch

import (
	"context"
	"sync"

	"github.com/rivo/tview"
)

// ChatUI represents all of the components in the terminal interface
type ChatUI struct {
	app              *tview.Application
	pages            *tview.Pages
	conversationList *tview.List
	messageView      *tview.TextView
	inputField       *tview.InputField
	statusBar        *tview.TextView
	ctx              context.Context
	messageHistory   map[string]LocalMessage
	mu               sync.RWMutex
	username         string
}

func NewChatUI(client *RpcClient) (*ChatUI, error) {
	ui := &ChatUI{}
	ui.app = tview.NewApplication()
	ui.pages = tview.NewPages()
	ui.conversationList = tview.NewList().ShowSecondaryText(false).SetHighlightFullLine(true)

	statusBar := tview.NewTextView().
		SetDynamicColors(true).
		SetText("[yellow]status:[white] Connected | [yellow]user:[white] myuser | [yellow]F1:[white] Chats [yellow]F2:[white] new chat [yellow]esc:[white] Quit")

	chatContent := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(ui.messageView, 0, 1, false).
		AddItem(ui.inputField, 1, 0, true)

	chatView := tview.NewFlex().
		AddItem(ui.conversationList, 20, 0, false).
		AddItem(chatContent, 0, 1, true)

	mainLayout := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(chatView, 0, 1, true).
		AddItem(statusBar, 1, 0, false)

	newChatForm := tview.NewForm().
		AddInputField("Username:", "", 20, nil, nil).
		AddButton("start Chat", func() {
			ui.pages.SwitchToPage("main")
		}).
		AddButton("cancel", func() {
			ui.pages.SwitchToPage("main")
		})

	newChatForm.SetBorder(true).SetTitle("New Chat").SetTitleAlign(tview.AlignCenter)

	newChatModal := tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(newChatForm, 7, 0, true).
			AddItem(nil, 0, 1, false), 40, 0, true).
		AddItem(nil, 0, 1, false)

	ui.pages.AddPage("main", mainLayout, true, true)
	ui.pages.AddPage("newchat", newChatModal, true, false)

	return &ChatUI{}, nil
}

// separate this function so we can also write tests for the app
func (ui *ChatUI) initWithData(conversations map[string][]LocalMessage) error {
	for user, messages := range conversations {
		ui.conversationList.AddItem(user, "", 0, nil)
	}

	return nil
}

func (ui *ChatUI) addConversation(username string) {
	idxs := ui.conversationList.FindItems(username, "", false, false)
	// ignore if it already exists
	if len(idxs) > 0 {
		return
	}

	ui.conversationList.AddItem(username, "", 0, nil)
}

func (ui *ChatUI) removeConversation(username string) {
	idxs := ui.conversationList.FindItems(username, "", false, false)
	// ignore if it doesn't exist
	if len(idxs) == 0 {
		return
	}

	for _, idx := range idxs {
		ui.conversationList.RemoveItem(idx)
	}
}
