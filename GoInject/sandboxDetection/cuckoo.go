//https://research.checkpoint.com/2022/invisible-cuckoo-cape-sandbox-evasion/

package sandboxDetection

import(
	"syscall"
	"unsafe"
	"golang.org/x/sys/windows"
)

var (
	advapi  = syscall.MustLoadDLL("Advapi32.dll")
	regLoadAppKeyW = advapi.MustFindProc("RegLoadAppKeyW")
	)

func DetectCuckooAndCAPE() bool {
	key := "testkey"
	keyUTF16, _ := windows.UTF16PtrFromString(key)
	var hKey uintptr
	KEY_ALL_ACCESS := 0xF003F
	_, _, err := regLoadAppKeyW.Call(uintptr(unsafe.Pointer(keyUTF16)), hKey, uintptr(KEY_ALL_ACCESS), 0, 0)
	if err.Error() != "The operation completed successfully." {
		return true
	}
	return false	
}