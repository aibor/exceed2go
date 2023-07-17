//go:build pidonetest

package bpf_test

import (
	"testing"

	"github.com/aibor/go-pidonetest"
)

func TestMain(m *testing.M) {
	pidonetest.Run(m)
}
