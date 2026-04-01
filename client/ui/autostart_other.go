//go:build !windows

package ui

func SetAutostart(enable bool) error                  { return nil }
func GetAutostart() bool                              { return false }
func SetAutoLogin(username, password string) error     { return nil }
func GetAutoLogin() (enabled bool, username string)    { return false, "" }
func AutoLoginSupported() bool                         { return false }
