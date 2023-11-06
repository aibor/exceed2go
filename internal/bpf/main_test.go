//go:build pidonetest

package bpf_test

import (
	"testing"

	"github.com/aibor/virtrun"
)

func TestMain(m *testing.M) {
	virtrun.Tests(m)
}
