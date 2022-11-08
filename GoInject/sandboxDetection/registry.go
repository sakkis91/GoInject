//taken from https://github.com/JustinTimperio/SandMan/blob/master/detection/virt_windows.go
package sandboxDetection

import(
	"golang.org/x/sys/windows/registry"
	"path/filepath"
	"strings"
	"os"
	"fmt"
	"errors"
)

func DetectRegistryKeys() bool {
	HyperV := []string{
		"HKLM\\SOFTWARE\\Microsoft\\Hyper-V",
		"HKLM\\SOFTWARE\\Microsoft\\VirtualMachine",
		"HKLM\\SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
		"HKLM\\SYSTEM\\ControlSet001\\Services\\vmicheartbeat",
		"HKLM\\SYSTEM\\ControlSet001\\Services\\vmicvss",
		"HKLM\\SYSTEM\\ControlSet001\\Services\\vmicshutdown",
		"HKLM\\SYSTEM\\ControlSet001\\Services\\vmicexchange",
	}

	VirtualBox := []string{
		"HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_80EE*",
		"HKLM\\HARDWARE\\ACPI\\DSDT\\VBOX__",
		"HKLM\\HARDWARE\\ACPI\\FADT\\VBOX__",
		"HKLM\\HARDWARE\\ACPI\\RSDT\\VBOX__",
		"HKLM\\SOFTWARE\\Oracle\\VirtualBox Guest Additions",
		"HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxGuest",
		"HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxMouse",
		"HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxService",
		"HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxSF",
		"HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxVideo",
	}

	VMware := []string{
		"HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_15AD*",
		"HKCU\\SOFTWARE\\VMware, Inc.\\VMware Tools",
		"HKLM\\SOFTWARE\\VMware, Inc.\\VMware Tools",
		"HKLM\\SYSTEM\\ControlSet001\\Services\\vmdebug",
		"HKLM\\SYSTEM\\ControlSet001\\Services\\vmmouse",
		"HKLM\\SYSTEM\\ControlSet001\\Services\\VMTools",
		"HKLM\\SYSTEM\\ControlSet001\\Services\\VMMEMCTL",
		"HKLM\\SYSTEM\\ControlSet001\\Services\\vmware",
		"HKLM\\SYSTEM\\ControlSet001\\Services\\vmci",
		"HKLM\\SYSTEM\\ControlSet001\\Services\\vmx86",
		"HKLM\\SYSTEM\\CurrentControlSet\\Enum\\IDE\\CdRomNECVMWar_VMware_IDE_CD*",
		"HKLM\\SYSTEM\\CurrentControlSet\\Enum\\IDE\\CdRomNECVMWar_VMware_SATA_CD*",
		"HKLM\\SYSTEM\\CurrentControlSet\\Enum\\IDE\\DiskVMware_Virtual_IDE_Hard_Drive*",
		"HKLM\\SYSTEM\\CurrentControlSet\\Enum\\IDE\\DiskVMware_Virtual_SATA_Hard_Drive*",
	}

	allKeys := [][]string{HyperV, VMware, VirtualBox}

	for _, keys := range allKeys {
		for _, key := range keys {
			if doesRegistryKeyExist(key) {
				return true
			}
		}
	}
	return false

}

func doesRegistryKeyExist(registryKey string) bool {

	subkeyPrefix := ""
	// Handle trailing wildcard
	if registryKey[len(registryKey)-1:] == "*" {
		registryKey, subkeyPrefix = filepath.Split(registryKey)
		subkeyPrefix = subkeyPrefix[:len(subkeyPrefix)-1] // remove *
	}

	keyType, keyPath, err := extractKeyTypeFrom(registryKey)
	if err != nil {
		//fmt.Println(err)
		return false
	}

	keyHandle, err := registry.OpenKey(keyType, keyPath, registry.QUERY_VALUE)
	if err != nil {
		// fmt.Println(fmt.Sprintf("Cannot open %v : %v", registryKey, err))
		return false
	}
	defer keyHandle.Close()

	// If a wildcard has been specified...
	if subkeyPrefix != "" {
		// we look for sub-keys to see if one exists
		subKeys, err := keyHandle.ReadSubKeyNames(0xFFFF)
		if err != nil {
			//fmt.Println(err)
			return false
		}

		for _, subKeyName := range subKeys {
			if strings.HasPrefix(subKeyName, subkeyPrefix) {
				return true
			}
		}

		return false
	} else {
		// The registryKey we were looking for has been found
		return true
	}
}

func extractKeyTypeFrom(registryKey string) (registry.Key, string, error) {
	firstSeparatorIndex := strings.Index(registryKey, string(os.PathSeparator))
	keyTypeStr := registryKey[:firstSeparatorIndex]
	keyPath := registryKey[firstSeparatorIndex+1:]

	var keyType registry.Key
	switch keyTypeStr {
	case "HKLM":
		keyType = registry.LOCAL_MACHINE
	case "HKCR":
		keyType = registry.CLASSES_ROOT
	case "HKCU":
		keyType = registry.CURRENT_USER
	case "HKU":
		keyType = registry.USERS
	case "HKCC":
		keyType = registry.CURRENT_CONFIG
	default:
		return keyType, "", errors.New(fmt.Sprintf("Invalid keytype (%v)", keyTypeStr))
	}

	return keyType, keyPath, nil
}