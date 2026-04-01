//go:build windows

package ui

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

const autostartName = "StunMax"

// SetAutostart creates a Windows Task Scheduler task that runs at logon with highest privileges.
func SetAutostart(enable bool) error {
	if enable {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		// Delete old task first (ignore error)
		runHiddenCmd("schtasks", "/Delete", "/TN", autostartName, "/F")

		// Create scheduled task: run at logon, highest privileges (admin)
		_, err = runHiddenCmd("schtasks", "/Create",
			"/TN", autostartName,
			"/TR", fmt.Sprintf(`"%s"`, exe),
			"/SC", "ONLOGON",
			"/RL", "HIGHEST",
			"/F",
		)
		if err != nil {
			// Fallback: registry Run key (no admin, but works)
			k, kerr := registry.OpenKey(registry.CURRENT_USER,
				`Software\Microsoft\Windows\CurrentVersion\Run`,
				registry.SET_VALUE)
			if kerr != nil {
				return err
			}
			defer k.Close()
			return k.SetStringValue(autostartName, exe)
		}
		return nil
	}

	// Disable: remove task and registry key
	runHiddenCmd("schtasks", "/Delete", "/TN", autostartName, "/F")
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		registry.SET_VALUE)
	if err == nil {
		k.DeleteValue(autostartName)
		k.Close()
	}
	return nil
}

// GetAutostart checks if autostart is enabled (task scheduler or registry).
func GetAutostart() bool {
	// Check task scheduler
	out, err := runHiddenCmd("schtasks", "/Query", "/TN", autostartName)
	if err == nil && strings.Contains(out, autostartName) {
		return true
	}
	// Check registry fallback
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue(autostartName)
	return err == nil
}

// SetAutoLogin configures Windows to auto-login with the given credentials.
// This sets the registry keys under Winlogon. Pass empty password to disable.
func SetAutoLogin(username, password string) error {
	if username == "" {
		// Disable auto-login
		k, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
			registry.SET_VALUE)
		if err != nil {
			return err
		}
		defer k.Close()
		k.SetStringValue("AutoAdminLogon", "0")
		k.DeleteValue("DefaultPassword")
		return nil
	}

	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
		registry.SET_VALUE)
	if err != nil {
		// Fallback: reg command
		runHiddenCmd("reg", "add",
			`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
			"/v", "AutoAdminLogon", "/t", "REG_SZ", "/d", "1", "/f")
		runHiddenCmd("reg", "add",
			`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
			"/v", "DefaultUserName", "/t", "REG_SZ", "/d", username, "/f")
		runHiddenCmd("reg", "add",
			`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
			"/v", "DefaultPassword", "/t", "REG_SZ", "/d", password, "/f")
		return nil
	}
	defer k.Close()

	k.SetStringValue("AutoAdminLogon", "1")
	k.SetStringValue("DefaultUserName", username)
	k.SetStringValue("DefaultPassword", password)
	return nil
}

// GetAutoLogin checks if auto-login is enabled.
func GetAutoLogin() (enabled bool, username string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
		registry.QUERY_VALUE)
	if err != nil {
		return false, ""
	}
	defer k.Close()
	val, _, err := k.GetStringValue("AutoAdminLogon")
	if err != nil || val != "1" {
		return false, ""
	}
	user, _, _ := k.GetStringValue("DefaultUserName")
	return true, user
}

// AutoLoginSupported returns true on Windows.
func AutoLoginSupported() bool { return true }

func runHiddenCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	return string(out), err
}
