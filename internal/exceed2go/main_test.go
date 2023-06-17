package exceed2go

import (
	"fmt"
	"os"
	"testing"

	"github.com/aibor/go-pidonetest"
)

func TestMain(m *testing.M) {
	rc, err := pidonetest.Run(m)
	if err != nil {
		fmt.Printf("Error: %v", err)
	}
	os.Exit(rc)
}
