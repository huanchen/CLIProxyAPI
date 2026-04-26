package auth

import (
	"context"
	"strings"
	"sync"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

const (
	monitorTriggerBuf       = 200
	monitorFailureThreshold = 2                // 时间窗口内 N 次错误才 disable
	monitorFailureWindow    = 10 * time.Minute // 失败计数有效窗口，窗口外重置
	monitorProbeInterval    = 2 * time.Minute  // recovery 首次 probe 间隔
	monitorMaxProbeInterval = 30 * time.Minute // probe 指数退避上限
	monitorScanInterval     = time.Minute      // 定时扫描间隔
	monitorScanBatch        = 3               // 每次扫描的 auth 数量
	monitorRefreshErrTag    = "auto_disabled"  // StatusMessage 标记前缀
)

// failureRecord 带时间窗口的失败计数。
type failureRecord struct {
	count     int
	windowEnd time.Time
}

// recoveryEntry recovery 队列条目，含指数退避状态。
type recoveryEntry struct {
	nextProbeAt time.Time
	probeCount  int // 探活失败次数，用于指数退避
}

type monitorEvent struct {
	authID   string
	provider string
	errCode  int
}

// AuthHealthMonitor 后台健康监控：异步 disable 错误账号，probe 恢复后自动 re-enable。
type AuthHealthMonitor struct {
	manager *cliproxyauth.Manager

	// 业务触发 channel（非阻塞，满了丢弃）
	triggerCh chan monitorEvent

	// 失败计数（时间窗口内）：authID -> *failureRecord
	failuresMu sync.Mutex
	failures   map[string]*failureRecord

	// 控制 TriggerRefresh 的发送频率：authID -> time.Time
	lastRefreshKick sync.Map

	// recovery 队列：authID -> recoveryEntry
	recoveryMu    sync.Mutex
	recoveryQueue map[string]recoveryEntry

	// 定时扫描游标（环形，分批处理）
	scanMu     sync.Mutex
	scanCursor int

	// 定时扫描失败计数（refresh 网络错误路径）：authID -> int
	scanFailures sync.Map

	stopCh chan struct{}
	once   sync.Once
}

func NewAuthHealthMonitor(manager *cliproxyauth.Manager) *AuthHealthMonitor {
	return &AuthHealthMonitor{
		manager:       manager,
		triggerCh:     make(chan monitorEvent, monitorTriggerBuf),
		failures:      make(map[string]*failureRecord),
		recoveryQueue: make(map[string]recoveryEntry),
		stopCh:        make(chan struct{}),
	}
}

func (m *AuthHealthMonitor) SetManager(mgr *cliproxyauth.Manager) {
	m.manager = mgr
}

func (m *AuthHealthMonitor) Start() {
	go m.runWorker()
	go m.runRecovery()
	go m.runScan()
}

func (m *AuthHealthMonitor) Stop() {
	m.once.Do(func() { close(m.stopCh) })
}

// Trigger 从 OnResult hook 非阻塞触发。
func (m *AuthHealthMonitor) Trigger(authID, provider string, errCode int) {
	if m == nil || authID == "" {
		return
	}
	select {
	case m.triggerCh <- monitorEvent{authID: authID, provider: provider, errCode: errCode}:
	default:
		// channel 满时丢弃，绝不阻塞主流程
	}
}

// ResetFailures 在业务请求成功时重置失败计数，防止历史失败累积误杀健康账号。
func (m *AuthHealthMonitor) ResetFailures(authID string) {
	if authID == "" {
		return
	}
	m.failuresMu.Lock()
	delete(m.failures, authID)
	m.failuresMu.Unlock()
	m.lastRefreshKick.Delete(authID)
}

// ---- worker ----

func (m *AuthHealthMonitor) runWorker() {
	for {
		select {
		case <-m.stopCh:
			return
		case evt := <-m.triggerCh:
			m.handleTrigger(evt)
		}
	}
}

func (m *AuthHealthMonitor) handleTrigger(evt monitorEvent) {
	if m.manager == nil || evt.authID == "" {
		return
	}
	// 429 quota exhausted：交给现有 cooldown 机制，不 disable
	if evt.errCode == 429 {
		return
	}

	// 先检查是否已 disabled，避免重复处理
	auth, ok := m.manager.GetByID(evt.authID)
	if !ok || auth == nil || auth.Disabled {
		return
	}

	// 时间窗口内累计失败次数
	now := time.Now()
	m.failuresMu.Lock()
	rec := m.failures[evt.authID]
	if rec == nil || now.After(rec.windowEnd) {
		// 窗口过期或首次：重新开窗口
		rec = &failureRecord{windowEnd: now.Add(monitorFailureWindow)}
		m.failures[evt.authID] = rec
	}
	rec.count++
	cnt := rec.count
	m.failuresMu.Unlock()

	if cnt < monitorFailureThreshold {
		// 未达阈值：限频踢一次 refresh（1min 内不重复）
		if last, ok := m.lastRefreshKick.Load(evt.authID); !ok || now.Sub(last.(time.Time)) > time.Minute {
			m.lastRefreshKick.Store(evt.authID, now)
			m.manager.TriggerRefresh(evt.authID)
		}
		return
	}

	// 达阈值：disable + 加入 recovery 队列
	if m.disableAndEnqueue(auth, monitorRefreshErrTag+":request_error") {
		m.failuresMu.Lock()
		delete(m.failures, evt.authID)
		m.failuresMu.Unlock()
		m.lastRefreshKick.Delete(evt.authID)
	}
}

// ---- recovery：每 30s 检查，并发 probe，指数退避 ----

func (m *AuthHealthMonitor) runRecovery() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.probeRecovery()
		}
	}
}

func (m *AuthHealthMonitor) probeRecovery() {
	if m.manager == nil {
		return
	}
	now := time.Now()

	m.recoveryMu.Lock()
	type dueItem struct {
		authID string
		entry  recoveryEntry
	}
	var due []dueItem
	for authID, entry := range m.recoveryQueue {
		if now.After(entry.nextProbeAt) {
			due = append(due, dueItem{authID, entry})
		}
	}
	m.recoveryMu.Unlock()

	// 并发 probe（ForceRefreshAuth 内有独立 singleflight 防重入）
	for _, item := range due {
		item := item
		go func() {
			// 30s timeout 防止 Google OAuth 无响应时 goroutine 永久阻塞
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := m.manager.ForceRefreshAuth(ctx, item.authID); err != nil {
				// auth 已被删除（从 manager 移除）：清出队列，不再重试
				if strings.Contains(err.Error(), "auth not found") {
					log.Infof("health-monitor: auth %s removed, dropping from recovery queue", maskSensitiveID(item.authID))
					m.recoveryMu.Lock()
					delete(m.recoveryQueue, item.authID)
					m.recoveryMu.Unlock()
					return
				}
				// 指数退避：2min → 4min → 8min → ... → 30min
				newCount := item.entry.probeCount + 1
				backoff := monitorProbeInterval * (1 << newCount)
				if backoff > monitorMaxProbeInterval {
					backoff = monitorMaxProbeInterval
				}
				log.Debugf("health-monitor probe: %s still failing (attempt %d), retry in %v: %v",
					maskSensitiveID(item.authID), newCount, backoff, err)
				m.recoveryMu.Lock()
				m.recoveryQueue[item.authID] = recoveryEntry{
					nextProbeAt: time.Now().Add(backoff),
					probeCount:  newCount,
				}
				m.recoveryMu.Unlock()
			} else {
				// ForceRefreshAuth 成功已 re-enable auth
				log.Infof("health-monitor: %s recovered and re-enabled", maskSensitiveID(item.authID))
				m.recoveryMu.Lock()
				delete(m.recoveryQueue, item.authID)
				m.recoveryMu.Unlock()
				m.scanFailures.Delete(item.authID)
			}
		}()
	}
}

// ---- scan：定时扫描 refresh 网络错误 ----

func (m *AuthHealthMonitor) runScan() {
	ticker := time.NewTicker(monitorScanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.scanRefreshErrors()
		}
	}
}

func (m *AuthHealthMonitor) scanRefreshErrors() {
	if m.manager == nil {
		return
	}
	all := m.manager.List()
	if len(all) == 0 {
		return
	}

	m.scanMu.Lock()
	total := len(all)
	start := m.scanCursor % total
	end := start + monitorScanBatch
	if end > total {
		end = total
	}
	m.scanCursor = end % total
	ids := make([]string, 0, end-start)
	for _, a := range all[start:end] {
		if a != nil {
			ids = append(ids, a.ID)
		}
	}
	m.scanMu.Unlock()

	now := time.Now()
	for _, id := range ids {
		// GetByID 拿最新状态，避免 List 快照过时
		auth, ok := m.manager.GetByID(id)
		if !ok || auth == nil || auth.Disabled {
			m.scanFailures.Delete(id) // 已 disabled，重置计数
			continue
		}
		if auth.LastError == nil || auth.NextRefreshAfter.IsZero() || !auth.NextRefreshAfter.After(now) {
			m.scanFailures.Delete(id) // 无退避 or 退避已过期：恢复正常，重置
			continue
		}
		if !isRefreshNetworkError(auth.LastError) {
			continue
		}

		var cnt int
		if v, ok := m.scanFailures.Load(id); ok {
			cnt = v.(int)
		}
		cnt++
		m.scanFailures.Store(id, cnt)

		if cnt >= monitorFailureThreshold {
			if m.disableAndEnqueue(auth, monitorRefreshErrTag+":refresh_net_error") {
				m.scanFailures.Delete(id)
			}
		}
	}
}

// ---- 内部工具 ----

// disableAndEnqueue disables the auth and adds it to the recovery queue.
// Returns true if disable succeeded.
func (m *AuthHealthMonitor) disableAndEnqueue(auth *cliproxyauth.Auth, reason string) bool {
	// 已在队列中不重复处理
	m.recoveryMu.Lock()
	_, alreadyQueued := m.recoveryQueue[auth.ID]
	m.recoveryMu.Unlock()
	if alreadyQueued {
		return false
	}

	auth.Disabled = true
	auth.Status = cliproxyauth.StatusDisabled
	auth.StatusMessage = reason
	auth.UpdatedAt = time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := m.manager.Update(ctx, auth); err != nil {
		log.Warnf("health-monitor: failed to disable %s: %v", maskSensitiveID(auth.ID), err)
		return false
	}
	log.Infof("health-monitor: disabled %s (%s)", maskSensitiveID(auth.ID), reason)

	m.recoveryMu.Lock()
	m.recoveryQueue[auth.ID] = recoveryEntry{
		nextProbeAt: time.Now().Add(monitorProbeInterval),
		probeCount:  0,
	}
	m.recoveryMu.Unlock()
	return true
}

func isRefreshNetworkError(e *cliproxyauth.Error) bool {
	if e == nil || e.HTTPStatus != 0 {
		return false
	}
	msg := strings.ToLower(e.Message)
	return strings.Contains(msg, "eof") ||
		strings.Contains(msg, "connection") ||
		strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "i/o") ||
		strings.Contains(msg, "dial")
}
