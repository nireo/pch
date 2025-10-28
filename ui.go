package pch

import (
	"context"
	"sync"

	"github.com/rivo/tview"
)

type ChatUI struct {
	app             *tview.Application
	client          *RpcClient
	pages           *tview.Pages
	converstionList *tview.List
	messagesView    *tview.TextView
	inputField      *tview.InputField
	statusBar       *tview.TextView
	ctx             context.Context
	messageHistory  map[string]LocalMessage
	messageChan     chan LocalMessage
	mu              sync.RWMutex
}
