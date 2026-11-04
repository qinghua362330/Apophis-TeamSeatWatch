//go:build linux

package platform

import "syscall"

// personalBrowserSysProcAttr keeps the browser process grouped with its
// allocator and kills it if the parent exits unexpectedly.
func personalBrowserSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}
