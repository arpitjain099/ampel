// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"testing"

	papi "github.com/policylabs/policy/api/v1"
	"github.com/stretchr/testify/require"
)

// Every driver answers for the statuses it can render: the human-readable
// ones render anything, the attestation-shaped ones only what their
// attestation format records.
func TestDriversSupportStatus(t *testing.T) {
	t.Parallel()
	LoadDefaultDrivers()
	verdicts := []string{papi.StatusPASS, papi.StatusFAIL, papi.StatusSOFTFAIL}
	for _, format := range Formats() {
		driver := GetDriverBytType(format)
		require.NotNil(t, driver, format)
		for _, status := range verdicts {
			require.True(t, driver.SupportsStatus(status), "%s must render %s", format, status)
		}
		require.False(t, driver.SupportsStatus(""), "%s: an empty status is not a status", format)
		wantSkip := format != "vsa" && format != "svr"
		require.Equal(t, wantSkip, driver.SupportsStatus(papi.StatusSKIP), "%s renders SKIP", format)
	}

	eng := NewEngine()
	require.NoError(t, eng.SetDriver("vsa"))
	require.False(t, eng.SupportsStatus(papi.StatusSKIP))
	require.NoError(t, eng.SetDriver("tty"))
	require.True(t, eng.SupportsStatus(papi.StatusSKIP))
}
