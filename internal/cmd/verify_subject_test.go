// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestVerifySubjectAlgorithms locks in the fix for policylabs/ampel#374:
// --subject must accept every in-toto DigestSet algorithm name, not just
// sha1/sha256/sha512, and must keep its canonical casing so the digest
// matches what the attestation matcher expects.
func TestVerifySubjectAlgorithms(t *testing.T) {
	t.Parallel()
	const (
		sha1Hex   = "16bc446f94bcef9093785f81897d2cfcbbcbe238"
		sha256Hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	)

	for _, tc := range []struct {
		name      string
		subject   string
		wantAlgo  string
		wantValue string
	}{
		{"gitCommit", "gitCommit:" + sha1Hex, "gitCommit", sha1Hex},
		{"gitTree", "gitTree:" + sha1Hex, "gitTree", sha1Hex},
		{"dirHash", "dirHash:" + sha256Hex, "dirHash", sha256Hex},
		{"sha3_256", "sha3_256:" + sha256Hex, "sha3_256", sha256Hex},
		{"md5", "md5:" + sha256Hex[:32], "md5", sha256Hex[:32]},
		{"case is normalized", "GitCommit:" + sha1Hex, "gitCommit", sha1Hex},
		{"sha256 still works", "sha256:" + sha256Hex, "sha256", sha256Hex},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cmd, opts := newVerifyCommand()
			require.NoError(t, cmd.PreRunE(cmd, []string{tc.subject}))
			require.Equal(t, tc.subject, opts.SubjectHash)
			require.Empty(t, opts.SubjectFile)

			rd, err := opts.SubjectDescriptor()
			require.NoError(t, err)
			require.Equal(t, map[string]string{tc.wantAlgo: tc.wantValue}, rd.GetDigest())
		})
	}
}

// TestVerifySubjectMalformedDigest checks that a digest-shaped subject is
// never looked up as a file: a bad digest is reported as such even when a
// file by that name sits in the working directory.
func TestVerifySubjectMalformedDigest(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sha256:abc"), []byte("x"), 0o600))
	t.Chdir(dir)

	for _, bad := range []string{"sha256:abc", "sha3:00", "gitCommit:zz"} {
		cmd, _ := newVerifyCommand()
		err := cmd.PreRunE(cmd, []string{bad})
		require.Error(t, err, bad)
		require.ErrorContains(t, err, "subject", bad)
	}

	// Spelled as a path, the same file is an ordinary file subject.
	cmd, opts := newVerifyCommand()
	require.NoError(t, cmd.PreRunE(cmd, []string{"./sha256:abc"}))
	require.Equal(t, "./sha256:abc", opts.SubjectFile)
	require.Empty(t, opts.SubjectHash)
}
