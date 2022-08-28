package ttlToGo

import (
	"os"
	"syscall"
	"testing"
)

func sysfs(t *testing.T) {
	if (os.Getpid() != 1) {
		return
	}

	if err := syscall.Mkdir("/sys", 0755); err != nil {
		t.Errorf("mkdir /sys: %v", err)
	}

	if err := syscall.Mount("sysfs", "/sys", "sysfs", uintptr(syscall.MS_NOEXEC), ""); err != nil {
		t.Errorf("mount /sys: %v", err)
	}
}

func poweroff() {
	if (os.Getpid() != 1) {
		return
	}

	syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
}


func TestLoad(t *testing.T) {
	sysfs(t)
	defer poweroff()
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Errorf("error loading objects: %v", err)
	}
	defer objs.Close()
}
