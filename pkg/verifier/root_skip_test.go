// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"testing"

	papi "github.com/policylabs/policy/api/v1"
	"github.com/stretchr/testify/require"
)

// The material handed to Verify is the root of the evaluation: unless skips
// are allowed, a root in which nothing was verified fails with ErrAllSkipped.
// Nested material keeps skipping.
func TestRootSkipFails(t *testing.T) {
	t.Parallel()
	allowing := func() *VerificationOptions {
		o := whenTestOptions()
		o.AllowSkip = true
		return o
	}
	block := func(id string, policies ...*papi.Policy) *papi.PolicyBlock {
		return &papi.PolicyBlock{Id: id, Meta: &papi.PolicyBlockMeta{}, Policies: policies}
	}
	group := func(blocks ...*papi.PolicyBlock) *papi.PolicyGroup {
		return &papi.PolicyGroup{Id: "grp", Meta: &papi.PolicyGroupMeta{}, Blocks: blocks}
	}

	for _, tc := range []struct {
		name     string
		material any
		// The status by default and with skips allowed.
		strict, allowed string
	}{
		{"policy-that-does-not-apply", gatedPolicy("no", "false"), papi.StatusFAIL, papi.StatusSKIP},
		{"policy-that-applies", gatedPolicy("yes", "true"), papi.StatusPASS, papi.StatusPASS},
		{"set-with-every-policy-skipped", &papi.PolicySet{Id: "set", Policies: []*papi.Policy{gatedPolicy("a", "false"), gatedPolicy("b", "false")}}, papi.StatusFAIL, papi.StatusSKIP},
		{"set-with-one-policy-applying", &papi.PolicySet{Id: "set", Policies: []*papi.Policy{gatedPolicy("a", "false"), gatedPolicy("b", "true")}}, papi.StatusPASS, papi.StatusPASS},
		{"group-with-every-block-skipped", group(block("x", gatedPolicy("a", "false")), block("y", gatedPolicy("b", "false"))), papi.StatusFAIL, papi.StatusSKIP},
		{"group-with-one-block-applying", group(block("x", gatedPolicy("a", "false")), block("y", gatedPolicy("b", "true"))), papi.StatusPASS, papi.StatusPASS},
		{"merged-sets-all-skipped", []*papi.PolicySet{
			{Id: "s1", Policies: []*papi.Policy{gatedPolicy("a", "false")}},
			{Id: "s2", Policies: []*papi.Policy{gatedPolicy("b", "false")}},
		}, papi.StatusFAIL, papi.StatusSKIP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ampel, err := New()
			require.NoError(t, err)

			strict, err := ampel.Verify(context.Background(), whenTestOptions(), tc.material, whenTestSubject())
			require.NoError(t, err)
			require.Equal(t, tc.strict, strict.GetStatus())
			require.Equal(t, tc.strict == papi.StatusFAIL, AllSkipped(strict), "the failure is recognizable as nothing verified")

			allowed, err := ampel.Verify(context.Background(), allowing(), tc.material, whenTestSubject())
			require.NoError(t, err)
			require.Equal(t, tc.allowed, allowed.GetStatus())
			require.False(t, AllSkipped(allowed))
		})
	}

	t.Run("the-failure-is-recorded-on-the-root-only", func(t *testing.T) {
		t.Parallel()
		ampel, err := New()
		require.NoError(t, err)
		set := &papi.PolicySet{Id: "set", Policies: []*papi.Policy{gatedPolicy("a", "false"), gatedPolicy("b", "false")}}
		res, err := ampel.Verify(context.Background(), whenTestOptions(), set, whenTestSubject())
		require.NoError(t, err)
		rs, ok := res.(*papi.ResultSet)
		require.True(t, ok)
		require.Equal(t, ErrAllSkipped.Error(), rs.GetError().GetMessage())
		require.Contains(t, rs.GetError().GetGuidance(), "AllowSkip")
		for _, r := range rs.GetResults() {
			require.Equal(t, papi.StatusSKIP, r.GetStatus(), "nested policies keep their skip")
			require.Equal(t, "when", r.GetEvalResults()[0].GetId())
		}
	})

	t.Run("a-failed-policy-records-the-skip-after-its-condition", func(t *testing.T) {
		t.Parallel()
		ampel, err := New()
		require.NoError(t, err)
		res, err := ampel.Verify(context.Background(), whenTestOptions(), gatedPolicy("no", "false"), whenTestSubject())
		require.NoError(t, err)
		r, ok := res.(*papi.Result)
		require.True(t, ok)
		require.Len(t, r.GetEvalResults(), 2)
		require.Equal(t, "when", r.GetEvalResults()[0].GetId())
		require.Equal(t, papi.StatusSKIP, r.GetEvalResults()[0].GetStatus())
		require.Equal(t, "skip", r.GetEvalResults()[1].GetId())
		require.Equal(t, papi.StatusFAIL, r.GetEvalResults()[1].GetStatus())
		require.Equal(t, ErrAllSkipped.Error(), r.GetEvalResults()[1].GetError().GetMessage())
	})

	t.Run("nested-entry-points-still-skip", func(t *testing.T) {
		t.Parallel()
		ampel, err := New()
		require.NoError(t, err)
		res, err := ampel.VerifySubjectWithPolicy(context.Background(), whenTestOptions(), gatedPolicy("no", "false"), whenTestSubject())
		require.NoError(t, err)
		require.Equal(t, papi.StatusSKIP, res.GetStatus())
		rs, err := ampel.VerifySubjectWithPolicySet(context.Background(), whenTestOptions(), &papi.PolicySet{Id: "set", Policies: []*papi.Policy{gatedPolicy("a", "false")}}, whenTestSubject())
		require.NoError(t, err)
		require.Equal(t, papi.StatusSKIP, rs.GetStatus())
	})
}
