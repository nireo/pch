package pch

import (
	"context"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// ChatUI represents all of the components in the terminal interface
type ChatUI struct {
	app              *tview.Application
	client           *RpcClient
	pages            *tview.Pages
	conversationList *tview.List
	messageView      *tview.TextView
	inputField       *tview.InputField
	statusBar        *tview.TextView
	ctx              context.Context
	cancel           context.CancelFunc
	messageHistory   map[string][]LocalMessage
	mu               sync.RWMutex
	username         string
	currentChat      string
}

// NewChatUI creates and initializes a new ChatUI instance
func NewChatUI(client *RpcClient, username string) (*ChatUI, error) {
	ctx, cancel := context.WithCancel(context.Background())

	ui := &ChatUI{
		client:         client,
		username:       username,
		ctx:            ctx,
		cancel:         cancel,
		messageHistory: make(map[string][]LocalMessage),
	}

	ui.app = tview.NewApplication()
	ui.pages = tview.NewPages()

	ui.conversationList = tview.NewList().
		ShowSecondaryText(false).
		SetHighlightFullLine(true)
	ui.conversationList.SetBorder(true).
		SetTitle("Conversations").
		SetTitleAlign(tview.AlignLeft)

	ui.messageView = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetChangedFunc(func() {
			ui.app.Draw()
		})
	ui.messageView.SetBorder(true).
		SetTitle("Messages").
		SetTitleAlign(tview.AlignLeft)

	ui.inputField = tview.NewInputField().
		SetLabel("> ").
		SetFieldWidth(0)
	ui.inputField.SetBorder(true).
		SetTitle("Send Message (Enter to send)").
		SetTitleAlign(tview.AlignLeft)

	ui.statusBar = tview.NewTextView().
		SetDynamicColors(true).
		SetText(fmt.Sprintf("[yellow]Status:[white] Connected | [yellow]User:[white] %s | [yellow]F1:[white] Chats [yellow]F2:[white] New Chat [yellow]Esc:[white] Quit", username))

	ui.inputField.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEnter {
			ui.sendMessage()
			return nil
		}
		return event
	})

	ui.conversationList.SetSelectedFunc(
		func(index int, mainText, secondaryText string, shortcut rune) {
			ui.selectConversation(mainText)
		},
	)

	chatContent := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(ui.messageView, 0, 1, false).
		AddItem(ui.inputField, 3, 0, true)

	chatView := tview.NewFlex().
		AddItem(ui.conversationList, 25, 0, false).
		AddItem(chatContent, 0, 1, true)

	mainLayout := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(chatView, 0, 1, true).
		AddItem(ui.statusBar, 1, 0, false)

	newChatForm := tview.NewForm()
	newChatForm.AddInputField("Username:", "", 30, nil, nil).
		AddButton("Start Chat", func() {
			username := newChatForm.GetFormItem(0).(*tview.InputField).GetText()
			if username != "" {
				ui.startNewChat(username)
			}
			ui.pages.SwitchToPage("main")
		}).
		AddButton("Cancel", func() {
			ui.pages.SwitchToPage("main")
		})
	newChatForm.SetBorder(true).
		SetTitle("New Chat").
		SetTitleAlign(tview.AlignCenter)

	newChatModal := tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(newChatForm, 9, 0, true).
			AddItem(nil, 0, 1, false), 50, 0, true).
		AddItem(nil, 0, 1, false)

	ui.pages.AddPage("main", mainLayout, true, true)
	ui.pages.AddPage("newchat", newChatModal, true, false)

	ui.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyF1:
			ui.app.SetFocus(ui.conversationList)
			return nil
		case tcell.KeyF2:
			ui.pages.SwitchToPage("newchat")
			ui.app.SetFocus(newChatForm)
			return nil
		case tcell.KeyEsc:
			if ui.pages.HasPage("newchat") {
				name, _ := ui.pages.GetFrontPage()
				if name == "newchat" {
					ui.pages.SwitchToPage("main")
					return nil
				}
			}
			ui.app.Stop()
			return nil
		}
		return event
	})

	ui.app.SetRoot(ui.pages, true)

	if err := ui.loadConversations(); err != nil {
		log.Printf("Warning: failed to load conversations: %v", err)
	}

	go ui.listenForMessages()
	return ui, nil
}

// loadConversations loads conversation history from local storage
func (ui *ChatUI) loadConversations() error {
	conversations, err := ui.client.localStore.GetAllMessages()
	if err != nil {
		return fmt.Errorf("failed to load conversations: %w", err)
	}

	return ui.initWithData(conversations)
}

// initWithData initializes the UI with existing conversation data
func (ui *ChatUI) initWithData(conversations map[string][]LocalMessage) error {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	for user, messages := range conversations {
		ui.conversationList.AddItem(user, "", 0, nil)
		ui.messageHistory[user] = messages
	}

	return nil
}

// selectConversation switches to the selected conversation
func (ui *ChatUI) selectConversation(username string) {
	ui.mu.Lock()
	ui.currentChat = username
	ui.mu.Unlock()

	ui.displayMessages(username)
	ui.messageView.SetTitle(fmt.Sprintf("Messages - %s", username))
	ui.app.SetFocus(ui.inputField)
}

// displayMessages shows message history for a conversation
func (ui *ChatUI) displayMessages(username string) {
	ui.mu.RLock()
	messages, ok := ui.messageHistory[username]
	ui.mu.RUnlock()

	if !ok {
		storedMessages, err := ui.client.localStore.GetMessages(username)
		if err != nil {
			log.Printf("Failed to load messages for %s: %v", username, err)
			ui.messageView.Clear()
			return
		}

		ui.mu.Lock()
		ui.messageHistory[username] = storedMessages
		messages = storedMessages
		ui.mu.Unlock()
	}

	// Sort messages by timestamp
	sort.Slice(messages, func(i, j int) bool {
		return messages[i].Timestamp.Before(messages[j].Timestamp)
	})

	ui.messageView.Clear()
	for _, msg := range messages {
		var sender string
		if msg.FromLocal {
			sender = "you"
		} else {
			sender = username
		}

		timestamp := msg.Timestamp.Format("15:04:05")
		fmt.Fprintf(ui.messageView, "[yellow]%s[white] [cyan]%s:[white] %s\n",
			timestamp, sender, msg.Content)
	}

	ui.messageView.ScrollToEnd()
}

func (ui *ChatUI) sendMessage() {
	text := ui.inputField.GetText()
	if text == "" {
		return
	}

	ui.mu.RLock()
	currentChat := ui.currentChat
	ui.mu.RUnlock()

	if currentChat == "" {
		ui.showStatus("No conversation selected", tcell.ColorRed)
		return
	}

	if !ui.client.HasConversation(currentChat) {
		if err := ui.client.InitiateChat(ui.ctx, currentChat); err != nil {
			ui.showStatus(fmt.Sprintf("failed to initiate chat: %v", err), tcell.ColorRed)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}

	if err := ui.client.SendMessage(currentChat, text); err != nil {
		ui.showStatus(fmt.Sprintf("failed to send message: %v", err), tcell.ColorRed)
		return
	}

	msg := LocalMessage{
		FromLocal: true,
		Content:   text,
		Timestamp: time.Now(),
	}

	ui.mu.Lock()
	ui.messageHistory[currentChat] = append(ui.messageHistory[currentChat], msg)
	ui.mu.Unlock()

	ui.inputField.SetText("")
	ui.displayMessages(currentChat)
}

// startNewChat initiates a new conversation
func (ui *ChatUI) startNewChat(username string) {
	ui.addConversation(username)

	ui.mu.Lock()
	if _, ok := ui.messageHistory[username]; !ok {
		ui.messageHistory[username] = []LocalMessage{}
	}
	ui.mu.Unlock()

	ui.selectConversation(username)
	ui.showStatus(fmt.Sprintf("started chat with %s", username), tcell.ColorGreen)
}

// addConversation adds a conversation to the list if it doesn't exist
func (ui *ChatUI) addConversation(username string) {
	idxs := ui.conversationList.FindItems(username, "", false, false)
	if len(idxs) > 0 {
		return
	}
	ui.conversationList.AddItem(username, "", 0, nil)
}

// removeConversation removes a conversation from the list
func (ui *ChatUI) removeConversation(username string) {
	idxs := ui.conversationList.FindItems(username, "", false, false)
	if len(idxs) == 0 {
		return
	}
	for _, idx := range idxs {
		ui.conversationList.RemoveItem(idx)
	}
}

// listenForMessages handles incoming messages
func (ui *ChatUI) listenForMessages() {
	ui.client.onMessageReceived = func(from, message string) {
		msg := LocalMessage{
			FromLocal: false,
			Content:   message,
			Timestamp: time.Now(),
		}

		ui.mu.Lock()
		ui.messageHistory[from] = append(ui.messageHistory[from], msg)
		currentChat := ui.currentChat
		ui.mu.Unlock()

		ui.app.QueueUpdateDraw(func() {
			ui.addConversation(from)

			if currentChat == from {
				ui.displayMessages(from)
			}
		})
	}
}

// showStatus displays a status message in the status bar
func (ui *ChatUI) showStatus(message string, color tcell.Color) {
	colorName := "white"
	switch color {
	case tcell.ColorGreen:
		colorName = "green"
	case tcell.ColorRed:
		colorName = "red"
	case tcell.ColorYellow:
		colorName = "yellow"
	}

	ui.app.QueueUpdateDraw(func() {
		ui.statusBar.SetText(fmt.Sprintf("[%s]%s", colorName, message))

		go func() {
			time.Sleep(3 * time.Second)
			ui.app.QueueUpdateDraw(func() {
				ui.statusBar.SetText(fmt.Sprintf(
					"[yellow]Status:[white] Connected | [yellow]User:[white] %s | [yellow]F1:[white] Chats [yellow]F2:[white] New Chat [yellow]Esc:[white] Quit",
					ui.username,
				))
			})
		}()
	})
}

// Run starts the UI event loop
func (ui *ChatUI) Run() error {
	return ui.app.Run()
}

// Stop gracefully stops the UI
func (ui *ChatUI) Stop() {
	ui.cancel()
	ui.app.Stop()
}

// GetCurrentConversation returns the currently selected conversation
func (ui *ChatUI) GetCurrentConversation() string {
	ui.mu.RLock()
	defer ui.mu.RUnlock()
	return ui.currentChat
}

// RefreshConversations reloads the conversation list
func (ui *ChatUI) RefreshConversations() error {
	conversations := ui.client.ListConversations()

	ui.app.QueueUpdateDraw(func() {
		ui.conversationList.Clear()
		for _, conv := range conversations {
			ui.addConversation(conv)
		}
	})

	return nil
}
