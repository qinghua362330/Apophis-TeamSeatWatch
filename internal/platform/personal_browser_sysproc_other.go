//go:build !linux

package platform

import "syscall"

// Pdeathsig is Linux-only. Other platforms still receive an explicit process
// attribute value so the browser launch remains portable.
func personalBrowserSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{}
}
