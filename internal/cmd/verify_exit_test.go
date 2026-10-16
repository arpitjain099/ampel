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
		expect   bool
	}{
		{"pass", papi.StatusPASS, true, false},
		{"softfail", papi.StatusSOFTFAIL, true, false},
		{"fail-with-exit-code", papi.StatusFAIL, true, true},
		{"fail-without-exit-code", papi.StatusFAIL, false, false},
		// A SKIP is only answered when --allow-skip asked for it.
		{"allowed-skip", papi.StatusSKIP, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := &verifyOptions{}
			opts.SetExitCode = tc.exitCode
			require.Equal(t, tc.expect, opts.exitNonZero(tc.status))
		})
	}
}

// The hidden --fail-skip keeps working: off, it allows skips.
func TestFailSkipMapsToAllowSkip(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name            string
		failSkip, allow bool
		expect          bool
	}{
		{"defaults", true, false, false},
		{"allow-skip", true, true, true},
		{"fail-skip-off", false, false, true},
		{"both", false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := &verifyOptions{FailSkip: tc.failSkip}
			opts.AllowSkip = tc.allow
			// The other options are unset, so validation fails; the mapping
			// happens before it does.
			require.Error(t, opts.Validate())
			require.Equal(t, tc.expect, opts.AllowSkip)
		})
	}
}
