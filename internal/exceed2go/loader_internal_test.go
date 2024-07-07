// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package exceed2go

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	pinDir := filepath.Join(bpffsDir, "test")
	require.NoError(t, os.MkdirAll(pinDir, 0o750))
	t.Cleanup(RemoveAll)

	objs, err := load(pinDir)
	require.NoError(t, err, "first load")
	t.Cleanup(func() { _ = objs.Close() })

	assert.FileExists(t, filepath.Join(pinDir, addrsMapName))
	assert.FileExists(t, filepath.Join(pinDir, statsMapName))
	require.NoError(t, objs.Close())

	objs, err = load(pinDir)
	require.NoError(t, err, "reload")
	t.Cleanup(func() { _ = objs.Close() })
}
