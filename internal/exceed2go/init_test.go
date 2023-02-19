//go:build pidone

package exceed2go

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func mountfs(m *testing.M, path, fstype string) error {
	if os.Getpid() != 1 {
		return nil
	}

	if err := os.MkdirAll(path, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %v", path, err)
	}

	if err := syscall.Mount("", path, fstype, 0, ""); err != nil {
		return fmt.Errorf("mount %s: %v", path, err)
	}

	return nil
}

func poweroff() {
	if os.Getpid() != 1 {
		return
	}

	if err := syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF); err != nil {
		fmt.Printf("error calling power off: %v\n", err)
	}
}

func run(m *testing.M) int {
	defer poweroff()
	fmt.Println("Init")

	mounts := []struct {
		dest   string
		fstype string
	}{
		{"/sys", "sysfs"},
		{"/sys/kernel/tracing", "tracefs"},
		{"/sys/fs/bpf", "bpf"},
		{"/proc", "proc"},
	}

	for _, mp := range mounts {
		if err := mountfs(m, mp.dest, mp.fstype); err != nil {
			fmt.Println(err)
			return 1
		}
		time.Sleep(200 * time.Millisecond)
	}

	if os.Getpid() == 1 {
		if err := os.WriteFile("/proc/sys/kernel/printk", []byte("0"), 0755); err != nil {
			fmt.Printf("setting printk: %v\n", err)
			return 1
		}
	}

	fmt.Println("Run tests")
	ret := m.Run()
	if os.Getpid() != 1 {
		return ret
	}
	fmt.Println("Print trace")
	f, err := os.ReadFile("/sys/kernel/tracing/trace")
	if err != nil {
		fmt.Printf("error opening trace pipe: %v\n", err)
		return ret
	}

	for _, l := range strings.Split(string(f), "\n") {
		if !strings.HasPrefix(l, "#") {
			fmt.Println(l)
		}
	}

	return ret
}

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

