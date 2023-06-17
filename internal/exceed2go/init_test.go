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

func mountfs(path, fstype string) error {
	if err := os.MkdirAll(path, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %v", path, err)
	}

	if err := syscall.Mount("", path, fstype, 0, ""); err != nil {
		return fmt.Errorf("mount %s: %v", path, err)
	}

	return nil
}

func setupSystem() error {
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
		if err := mountfs(mp.dest, mp.fstype); err != nil {
			return err
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Silence the kernel so it does not show up in our test output.
	if err := os.WriteFile("/proc/sys/kernel/printk", []byte("0"), 0755); err != nil {
		return fmt.Errorf("set printk: %v", err)
	}

	return nil
}

func printTrace() error {
	f, err := os.ReadFile("/sys/kernel/tracing/trace")
	if err != nil {
		return fmt.Errorf("open trace pipe: %v", err)
	}

	log := make([]string, 0)
	for _, l := range strings.Split(strings.TrimSpace(string(f)), "\n") {
		if !strings.HasPrefix(l, "#") {
			log = append(log, l)
		}
	}

	if len(log) > 0 {
		fmt.Println("Kernel trace log:")
		fmt.Println(f)
	}

	return nil
}

func poweroff() {
	if err := syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF); err != nil {
		fmt.Printf("error calling power off: %v\n", err)
	}
}

func run(m *testing.M) int {
	isPidOne := os.Getpid() == 1

	if isPidOne {
		defer poweroff()

		if err := setupSystem(); err != nil {
			fmt.Printf("Error setting up system: %v\n", err)
			return 1
		}
	}

	ret := m.Run()

	if isPidOne && testing.Verbose() {
		if err := printTrace(); err != nil {
			fmt.Printf("Error printing trace: %v\n", err)
		}
	}

	fmt.Printf("PIDONE_GO_TEST_RC: %d\n", ret)
	return ret
}

func TestMain(m *testing.M) {
	os.Exit(run(m))
}
