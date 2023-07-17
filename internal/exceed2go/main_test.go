//go:build pidonetest

package exceed2go_test

import (
	"testing"

	"github.com/aibor/go-pidonetest"
)

func TestMain(m *testing.M) {
	pidonetest.Run(m)
}
