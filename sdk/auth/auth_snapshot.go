package auth

import (
	"sort"
	"sync"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

// AuthSnapshot 通过 Hook 回调（OnAuthRegistered/OnAuthUpdated）维护 auth 列表快照。
// 这些回调在 manager 写锁释放后才调用，所以 AuthSnapshot 自身的锁极轻，
// 不会与 manager 的全局锁产生竞争，彻底消除 manager.List() 的 30s 卡顿。
type AuthSnapshot struct {
	mu    sync.RWMutex
	auths map[string]*cliproxyauth.Auth // authID -> latest clone
}

func NewAuthSnapshot() *AuthSnapshot {
	return &AuthSnapshot{auths: make(map[string]*cliproxyauth.Auth)}
}

// OnAuthRegistered 在新 auth 注册时更新快照。
func (s *AuthSnapshot) OnAuthRegistered(auth *cliproxyauth.Auth) {
	if auth == nil || auth.ID == "" {
		return
	}
	s.mu.Lock()
	s.auths[auth.ID] = auth.Clone()
	s.mu.Unlock()
}

// OnAuthUpdated 在 auth 状态变更时更新快照。
func (s *AuthSnapshot) OnAuthUpdated(auth *cliproxyauth.Auth) {
	if auth == nil || auth.ID == "" {
		return
	}
	s.mu.Lock()
	s.auths[auth.ID] = auth.Clone()
	s.mu.Unlock()
}

// OnAuthRemoved 在 auth 被删除时从快照移除。
func (s *AuthSnapshot) OnAuthRemoved(authID string) {
	if authID == "" {
		return
	}
	s.mu.Lock()
	delete(s.auths, authID)
	s.mu.Unlock()
}

// List 返回当前快照的所有 auth，不涉及 manager 锁。
func (s *AuthSnapshot) List() []*cliproxyauth.Auth {
	s.mu.RLock()
	out := make([]*cliproxyauth.Auth, 0, len(s.auths))
	for _, a := range s.auths {
		out = append(out, a)
	}
	s.mu.RUnlock()
	return out
}

// ListSorted 返回按 name 排序的快照列表。
func (s *AuthSnapshot) ListSorted() []*cliproxyauth.Auth {
	list := s.List()
	sort.Slice(list, func(i, j int) bool {
		ni := list[i].FileName
		if ni == "" {
			ni = list[i].ID
		}
		nj := list[j].FileName
		if nj == "" {
			nj = list[j].ID
		}
		return ni < nj
	})
	return list
}

// Len 返回当前快照的 auth 数量。
func (s *AuthSnapshot) Len() int {
	s.mu.RLock()
	n := len(s.auths)
	s.mu.RUnlock()
	return n
}
