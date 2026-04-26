package auth

import (
	"sync"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

const backupSubDir = "401-bak"

// BackupScanner is kept for API compatibility but performs no action.
// 401 handling is now done manually via the management UI.
type BackupScanner struct {
	manager  *cliproxyauth.Manager
	interval time.Duration
	stopCh   chan struct{}
	once     sync.Once
}

// NewBackupScanner creates a scanner (currently no-op, automatic logic removed).
func NewBackupScanner(store *FileTokenStore, manager *cliproxyauth.Manager, interval time.Duration) *BackupScanner {
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	return &BackupScanner{
		manager:  manager,
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

// Start begins the periodic scan loop (no-op).
func (bs *BackupScanner) Start() {}

// Stop terminates the background scan loop.
func (bs *BackupScanner) Stop() {
	bs.once.Do(func() { close(bs.stopCh) })
}

func maskSensitiveID(id string) string {
	if len(id) <= 8 {
		return "***"
	}
	return id[:4] + "***" + id[len(id)-3:]
}
