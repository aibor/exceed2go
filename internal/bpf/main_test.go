//go:build pidonetest

package bpf_test

import (
	"testing"

	"github.com/aibor/pidonetest"
)

func TestMain(m *testing.M) {
	pidonetest.RunTests(m)
}
