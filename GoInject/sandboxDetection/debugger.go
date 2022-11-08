package sandboxDetection

import(
	"syscall"
)

var (
	kernel32  = syscall.MustLoadDLL("kernel32.dll")
	isDebuggerPresent = kernel32.MustFindProc("IsDebuggerPresent")
)

func IsBeingDebugged() bool {
	ret, _, _ := isDebuggerPresent.Call()
	if ret != 0 {
		return true
	}
	return false
}