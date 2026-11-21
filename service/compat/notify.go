package compat

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/packettale/agents/base/config"
	"github.com/packettale/agents/base/log"
	"github.com/packettale/agents/base/notifications"
	"github.com/packettale/agents/service/mgr"
	"github.com/packettale/agents/service/process"
	"github.com/packettale/agents/service/profile"
)

type baseIssue struct {
	id      string                  //nolint:structcheck // Inherited.
	title   string                  //nolint:structcheck // Inherited.
	message string                  //nolint:structcheck // Inherited.
	level   notifications.Type      //nolint:structcheck // Inherited.
	actions []*notifications.Action //nolint:structcheck // Inherited.
}

type systemIssue baseIssue

type appIssue baseIssue

var (
	// Copy of firewall.CfgOptionDNSQueryInterceptionKey.
	cfgOptionDNSQueryInterceptionKey = "filter/dnsQueryInterception"
	dnsQueryInterception             config.BoolOption

	systemIssueNotification     *notifications.Notification
	systemIssueNotificationLock sync.Mutex

	systemIntegrationIssue = &systemIssue{
		id:      "compat:system-integration-issue",
		title:   "Detected System Integration Issue",
		message: "packettale detected a problem with system integration. Restart or reinstall the application, then contact your administrator if the problem continues.",
		level:   notifications.Error,
	}
	systemCompatibilityIssue = &systemIssue{
		id:      "compat:compatibility-issue",
		title:   "Detected Compatibility Issue",
		message: "packettale detected software that interferes with its operation. Check VPN, antivirus, and other network protection software, then contact your administrator if the problem continues.",
		level:   notifications.Error,
	}
	// manualDNSSetupRequired is additionally initialized in startNotify().
	manualDNSSetupRequired = &systemIssue{
		id:    "compat:manual-dns-setup-required",
		title: "Manual DNS Setup Required",
		level: notifications.Error,
		actions: []*notifications.Action{
			{
				Text: "Revert",
				Type: notifications.ActionTypeOpenSetting,
				Payload: &notifications.ActionTypeOpenSettingPayload{
					Key: cfgOptionDNSQueryInterceptionKey,
				},
			},
		},
	}
	manualDNSSetupRequiredMessage = "Seamless DNS Integration is disabled, so DNS filtering may not work reliably. Configure %s as the DNS server in the system and any conflicting application. This message will disappear after correct configuration."

	secureDNSBypassIssue = &appIssue{
		id:      "compat:secure-dns-bypass-%s",
		title:   "Blocked Bypass Attempt by %s",
		message: `[APPNAME] is using its own Secure DNS resolver, which would bypass packettale's DNS protection. If [APPNAME] experiences problems, disable Secure DNS within that app. packettale handles Secure DNS for this device.`,
		// TODO: Add this when the new docs page is finished:
		// , or [find out about other options](link to new docs page)
		level: notifications.Warning,
	}
)

func startNotify() {
	dnsQueryInterception = config.Concurrent.GetAsBool(cfgOptionDNSQueryInterceptionKey, true)

	systemIssueNotificationLock.Lock()
	defer systemIssueNotificationLock.Unlock()

	manualDNSSetupRequired.message = fmt.Sprintf(
		manualDNSSetupRequiredMessage,
		`"127.0.0.1"`,
	)
}

// SetNameserverListenIP sets the IP address the nameserver is listening on.
// The IP address is used in compatibility notifications.
func SetNameserverListenIP(ip net.IP) {
	systemIssueNotificationLock.Lock()
	defer systemIssueNotificationLock.Unlock()

	manualDNSSetupRequired.message = fmt.Sprintf(
		manualDNSSetupRequiredMessage,
		`"`+ip.String()+`"`,
	)
}

func systemCompatOrManualDNSIssue() *systemIssue {
	if dnsQueryInterception() {
		return systemCompatibilityIssue
	}
	return manualDNSSetupRequired
}

func (issue *systemIssue) notify(err error) { //nolint // TODO: Should we use the error?
	systemIssueNotificationLock.Lock()
	defer systemIssueNotificationLock.Unlock()

	if systemIssueNotification != nil {
		// Ignore duplicate notification.
		if issue.id == systemIssueNotification.EventID {
			return
		}

		// Remove old notification.
		systemIssueNotification.Delete()
	}

	// Create new notification.
	n := &notifications.Notification{
		EventID:          issue.id,
		Type:             issue.level,
		Title:            issue.title,
		Message:          issue.message,
		AvailableActions: issue.actions,
	}
	notifications.Notify(n)

	systemIssueNotification = n
	n.SyncWithState(module.states)
}

func resetSystemIssue() {
	systemIssueNotificationLock.Lock()
	defer systemIssueNotificationLock.Unlock()

	if systemIssueNotification != nil {
		systemIssueNotification.Delete()
	}
	systemIssueNotification = nil
}

func (issue *appIssue) notify(proc *process.Process) {
	// Get profile from process.
	p := proc.Profile().LocalProfile()
	if p == nil {
		return
	}

	// Ignore notifications for unidentified processes.
	if p.ID == profile.UnidentifiedProfileID {
		return
	}

	// Log warning.
	log.Warningf(
		"compat: detected %s issue with %s",
		strings.ReplaceAll(
			strings.TrimPrefix(
				strings.TrimSuffix(issue.id, "-%s"),
				"compat:",
			),
			"-", " ",
		),
		proc.Path,
	)

	// Check if we already have this notification.
	eventID := fmt.Sprintf(issue.id, p.ID)
	n := notifications.Get(eventID)
	if n != nil {
		return
	}

	// Check if we reach the threshold to actually send a notification.
	if !isOverThreshold(eventID) {
		return
	}

	// Build message.
	message := strings.ReplaceAll(issue.message, "[APPNAME]", p.Name)

	// Create a new notification.
	n = &notifications.Notification{
		EventID:          eventID,
		Type:             issue.level,
		Title:            fmt.Sprintf(issue.title, p.Name),
		Message:          message,
		AvailableActions: issue.actions,
	}
	if len(n.AvailableActions) == 0 {
		n.AvailableActions = []*notifications.Action{
			{
				ID:   "ack",
				Text: "OK",
			},
		}
	}
	notifications.Notify(n)

	// Set warning on profile.
	module.mgr.Go("set app compat warning", func(ctx *mgr.WorkerCtx) error {
		var changed bool

		func() {
			p.Lock()
			defer p.Unlock()

			if p.Warning != message || time.Now().Add(-1*time.Hour).After(p.WarningLastUpdated) {
				p.Warning = message
				p.WarningLastUpdated = time.Now()
				changed = true
			}
		}()

		if changed {
			return p.Save()
		}
		return nil
	})
}

const (
	notifyThresholdMinIncidents = 10
	notifyThresholdResetAfter   = 2 * time.Minute
)

var (
	notifyThresholds     = make(map[string]*notifyThreshold)
	notifyThresholdsLock sync.Mutex
)

type notifyThreshold struct {
	FirstSeen time.Time
	Incidents uint
}

func (nt *notifyThreshold) expired() bool {
	return time.Now().Add(-notifyThresholdResetAfter).After(nt.FirstSeen)
}

func isOverThreshold(id string) bool {
	notifyThresholdsLock.Lock()
	defer notifyThresholdsLock.Unlock()

	// Get notify threshold and check if we reach the minimum incidents.
	nt, ok := notifyThresholds[id]
	if ok && !nt.expired() {
		nt.Incidents++
		return nt.Incidents >= notifyThresholdMinIncidents
	}

	// Add new entry.
	notifyThresholds[id] = &notifyThreshold{
		FirstSeen: time.Now(),
		Incidents: 1,
	}
	return false
}

func cleanNotifyThreshold(ctx *mgr.WorkerCtx) error {
	notifyThresholdsLock.Lock()
	defer notifyThresholdsLock.Unlock()

	for id, nt := range notifyThresholds {
		if nt.expired() {
			delete(notifyThresholds, id)
		}
	}

	return nil
}
