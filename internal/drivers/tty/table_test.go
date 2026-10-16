// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package tty

import (
	"bytes"
	"testing"

	papi "github.com/policylabs/policy/api/v1"
	"github.com/stretchr/testify/require"
)

// pass builds a passing policy result carrying one assessment per message.
func pass(msgs ...string) *papi.Result {
	res := &papi.Result{Status: papi.StatusPASS}
	for _, m := range msgs {
		res.EvalResults = append(res.EvalResults, &papi.EvalResult{
			Status:     papi.StatusPASS,
			Assessment: &papi.Assessment{Message: m},
		})
	}
	return res
}

// fail builds a failing policy result carrying one error per message.
func fail(msgs ...string) *papi.Result {
	res := &papi.Result{Status: papi.StatusFAIL}
	for _, m := range msgs {
		res.EvalResults = append(res.EvalResults, &papi.EvalResult{
			Status: papi.StatusFAIL,
			Error:  &papi.Error{Message: m},
		})
	}
	return res
}

func TestBlockAssessments(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		assertMode string
		results    []*papi.Result
		expected   []string
	}{
		{
			name:     "single policy",
			results:  []*papi.Result{pass("SBOM is signed")},
			expected: []string{"SBOM is signed"},
		},
		{
			// Default (AND) mode: every policy had to pass, so report all.
			name:       "and mode reports every policy",
			assertMode: "",
			results:    []*papi.Result{pass("has author"), pass("has timestamp")},
			expected:   []string{"has author", "has timestamp"},
		},
		{
			name:       "explicit and mode reports every policy",
			assertMode: "AND",
			results:    []*papi.Result{pass("has author"), pass("has timestamp")},
			expected:   []string{"has author", "has timestamp"},
		},
		{
			// OR mode: only the policy that carried the block is reported.
			name:       "or mode reports only the deciding policy",
			assertMode: "OR",
			results:    []*papi.Result{fail("no purl"), pass("has CPE")},
			expected:   []string{"has CPE"},
		},
		{
			name:       "or mode stops at the first passing policy",
			assertMode: "OR",
			results:    []*papi.Result{pass("has purl"), pass("has CPE")},
			expected:   []string{"has purl"},
		},
		{
			// A silent deciding policy must not blank the cell when a later
			// passing policy has something to report.
			name:       "or mode skips a passing policy with no message",
			assertMode: "OR",
			results:    []*papi.Result{pass(), pass("has CPE")},
			expected:   []string{"has CPE"},
		},
		{
			name:       "failed policies are ignored",
			assertMode: "AND",
			results:    []*papi.Result{pass("has author"), fail("no license")},
			expected:   []string{"has author"},
		},
		{
			name:     "duplicate messages are collapsed",
			results:  []*papi.Result{pass("has author"), pass("has author")},
			expected: []string{"has author"},
		},
		{
			name:     "no assessment messages",
			results:  []*papi.Result{pass()},
			expected: []string{},
		},
		{
			name:     "no results",
			results:  []*papi.Result{},
			expected: []string{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			block := &papi.BlockEvalResult{
				Status:  papi.StatusPASS,
				Meta:    &papi.PolicyBlockMeta{AssertMode: tc.assertMode},
				Results: tc.results,
			}
			require.Equal(t, tc.expected, blockAssessments(block))
		})
	}
}

// A policy in OR assert mode passes with some of its tenets failing. Only
// the tenets that actually passed carry an assessment worth showing.
func TestBlockAssessmentsSkipsFailedTenets(t *testing.T) {
	t.Parallel()
	block := &papi.BlockEvalResult{
		Status: papi.StatusPASS,
		Meta:   &papi.PolicyBlockMeta{},
		Results: []*papi.Result{
			{
				Status: papi.StatusPASS,
				EvalResults: []*papi.EvalResult{
					{Status: papi.StatusFAIL, Error: &papi.Error{Message: "no purl"}},
					{Status: papi.StatusPASS, Assessment: &papi.Assessment{Message: "has CPE"}},
				},
			},
		},
	}
	require.Equal(t, []string{"has CPE"}, blockAssessments(block))
}

// TestResultTableSkip checks that a skipped policy's row shows the skip
// reason instead of an empty error cell.
func TestResultTableSkip(t *testing.T) {
	t.Parallel()
	res := &papi.Result{
		Status: papi.StatusSKIP,
		Policy: &papi.PolicyRef{Id: "prod-only"},
		Meta:   &papi.Meta{Description: "Only for production releases"},
		EvalResults: []*papi.EvalResult{{
			Id: "when", Status: papi.StatusSKIP,
			Assessment: &papi.Assessment{Message: "Skipped: condition \"context.env == 'prod'\" is false"},
		}},
	}
	var buf bytes.Buffer
	_, err := New().resultTable(res).WriteTo(&buf)
	require.NoError(t, err)
	out := buf.String()
	require.Contains(t, out, "SKIP")
	require.Contains(t, out, "Skipped: condition")
	require.Contains(t, out, "none evaluated, policy skipped", "a skip ran no tenet")
	require.Contains(t, out, "when", "the check column names the condition")

	// The failure a skip set aside is a second, named row.
	res.EvalResults = append(res.EvalResults, &papi.EvalResult{
		Id: "evidence", Status: papi.StatusSKIP,
		Assessment: &papi.Assessment{Message: "Evidence not verified: attestation identity validation failed"},
		Error:      &papi.Error{Message: "attestation identity validation failed"},
	})
	buf.Reset()
	_, err = New().resultTable(res).WriteTo(&buf)
	require.NoError(t, err)
	out = buf.String()
	require.Contains(t, out, "evidence")
	require.Contains(t, out, "Evidence not verified")
	require.Contains(t, out, "none evaluated, policy skipped")
}

// TestResultTableCheckIDs checks that a policy without controls still names
// its checks: by tenet id, or by position for a tenet without one.
func TestResultTableCheckIDs(t *testing.T) {
	t.Parallel()
	res := &papi.Result{
		Status: papi.StatusPASS,
		Policy: &papi.PolicyRef{Id: "sbom"},
		Meta:   &papi.Meta{Description: "SBOM checks"},
		EvalResults: []*papi.EvalResult{
			{Id: "has-packages", Status: papi.StatusPASS, Assessment: &papi.Assessment{Message: "SBOM lists packages"}},
			{Status: papi.StatusPASS, Assessment: &papi.Assessment{Message: "SBOM has an author"}},
		},
	}
	var buf bytes.Buffer
	_, err := New().resultTable(res).WriteTo(&buf)
	require.NoError(t, err)
	out := buf.String()
	require.Contains(t, out, "has-packages")
	require.Contains(t, out, "#1", "a tenet without an id is named by its position")
	require.Contains(t, out, "2 (2 PASS)", "the tenet count is unchanged for an evaluated policy")
}
