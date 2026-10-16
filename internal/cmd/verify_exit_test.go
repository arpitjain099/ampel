// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"

	papi "github.com/policylabs/policy/api/v1"
	"github.com/stretchr/testify/require"
)

func TestExitNonZero(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		status   string
		exitCode bool
		failSkip bool
		expect   bool
	}{
		{"pass", papi.StatusPASS, true, true, false},
		{"softfail", papi.StatusSOFTFAIL, true, true, false},
		{"fail-with-exit-code", papi.StatusFAIL, true, false, true},
		{"fail-without-exit-code", papi.StatusFAIL, false, true, false},
		// A SKIP is only answered when --allow-skip asked for it; it exits
		// zero unless --fail-skip wants scripts to block on it too.
		{"allowed-skip", papi.StatusSKIP, true, false, false},
		{"allowed-skip-with-fail-skip", papi.StatusSKIP, true, true, true},
		{"exit-code-off-disables-fail-skip", papi.StatusSKIP, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := &verifyOptions{FailSkip: tc.failSkip}
			opts.SetExitCode = tc.exitCode
			require.Equal(t, tc.expect, opts.exitNonZero(tc.status))
		})
	}
}

// Without --allow-skip a run never answers SKIP, so --fail-skip changes
// nothing: it does not turn skips on, and the root still fails on its own.
func TestFailSkipNeedsAllowSkip(t *testing.T) {
	t.Parallel()
	opts := &verifyOptions{FailSkip: true}
	require.Error(t, opts.Validate()) // the other options are unset
	require.False(t, opts.AllowSkip)
	require.Equal(t, []string{papi.StatusPASS, papi.StatusFAIL, papi.StatusSOFTFAIL}, opts.possibleStatuses())
}
