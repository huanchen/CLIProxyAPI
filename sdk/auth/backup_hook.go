package auth

import (
	"context"
	"sync/atomic"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

// BackupOnUnauthorizedHook wraps an existing Hook and forwards antigravity
// 40x/50x results to the AuthHealthMonitor for async disable + recovery.
type BackupOnUnauthorizedHook struct {
	inner   cliproxyauth.Hook
	monitor *AuthHealthMonitor
	enabled atomic.Bool
}

// NewBackupOnUnauthorizedHook creates the hook. monitor may be nil initially
// and set later via SetMonitor.
func NewBackupOnUnauthorizedHook(inner cliproxyauth.Hook, manager *cliproxyauth.Manager, enabled bool) *BackupOnUnauthorizedHook {
	if inner == nil {
		inner = cliproxyauth.NoopHook{}
	}
	h := &BackupOnUnauthorizedHook{inner: inner}
	h.enabled.Store(enabled)
	return h
}

// SetMonitor injects the health monitor after it is created.
func (h *BackupOnUnauthorizedHook) SetMonitor(m *AuthHealthMonitor) { h.monitor = m }

// SetManager is a no-op kept for API compatibility.
func (h *BackupOnUnauthorizedHook) SetManager(_ *cliproxyauth.Manager) {}

// SetEnabled toggles the feature at runtime.
func (h *BackupOnUnauthorizedHook) SetEnabled(v bool) { h.enabled.Store(v) }

func (h *BackupOnUnauthorizedHook) OnAuthRegistered(ctx context.Context, auth *cliproxyauth.Auth) {
	h.inner.OnAuthRegistered(ctx, auth)
}

func (h *BackupOnUnauthorizedHook) OnAuthUpdated(ctx context.Context, auth *cliproxyauth.Auth) {
	h.inner.OnAuthUpdated(ctx, auth)
}

func (h *BackupOnUnauthorizedHook) OnResult(ctx context.Context, result cliproxyauth.Result) {
	h.inner.OnResult(ctx, result)

	if h.monitor == nil {
		return
	}
	if result.Provider != "antigravity" || result.AuthID == "" {
		return
	}
	// 成功时重置失败计数，防止历史失败累积误杀健康账号
	if result.Success {
		h.monitor.ResetFailures(result.AuthID)
		return
	}
	if !h.enabled.Load() || result.Error == nil {
		return
	}
	code := result.Error.HTTPStatus
	if code == 401 || code == 402 || code == 403 ||
		code == 500 || code == 502 || code == 503 || code == 504 {
		h.monitor.Trigger(result.AuthID, result.Provider, code)
	}
}
