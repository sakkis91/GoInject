package sandboxDetection

import(
	"os"
)

func DetectSystemFiles() bool {
	VirtualBox := []string{
		"C:\\windows\\system32\\drivers\\VBoxMouse.sys",
		"C:\\windows\\system32\\drivers\\VBoxGuest.sys",
		"C:\\windows\\system32\\drivers\\VBoxSF.sys",
		"C:\\windows\\system32\\drivers\\VBoxVideo.sys",
		"C:\\windows\\system32\\vboxdisp.dll",
		"C:\\windows\\system32\\vboxhook.dll",
		"C:\\windows\\system32\\vboxmrxnp.dll",
		"C:\\windows\\system32\\vboxogl.dll",
		"C:\\windows\\system32\\vboxoglarrayspu.dll",
		"C:\\windows\\system32\\vboxoglcrutil.dll",
		"C:\\windows\\system32\\vboxoglerrorspu.dll",
		"C:\\windows\\system32\\vboxoglfeedbackspu.dll",
		"C:\\windows\\system32\\vboxoglpackspu.dll",
		"C:\\windows\\system32\\vboxoglpassthroughspu.dll",
		"C:\\windows\\system32\\vboxservice.exe",
		"C:\\windows\\system32\\vboxtray.exe",
		"C:\\windows\\system32\\VBoxControl.exe",
	}

	VMware := []string{
		"C:\\windows\\system32\\drivers\\vmmouse.sys",
		"C:\\windows\\system32\\drivers\\vmnet.sys",
		"C:\\windows\\system32\\drivers\\vmxnet.sys",
		"C:\\windows\\system32\\drivers\\vmhgfs.sys",
		"C:\\windows\\system32\\drivers\\vmx86.sys",
		"C:\\windows\\system32\\drivers\\hgfs.sys",
	}

	// Hyper-V := []string{
	// 	"C:\\windows\\system32\\vmcompute.exe"
	// }

	combined := [][]string{VMware, VirtualBox}
	for _, systemFiles := range combined {
		for _, sf := range systemFiles {
			if DoesPathExist(sf) {
				return true
			}
		}
	}
	return false

}

	func DoesPathExist(path string) bool {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false
		} else {
			return true
		}
	}
	return true
}