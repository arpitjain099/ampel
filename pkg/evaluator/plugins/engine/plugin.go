// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"cel.dev/cel-go/cel"
	"github.com/policylabs/attestation"
	papi "github.com/policylabs/policy/api/v1"

	api "github.com/policylabs/ampel/pkg/api/v1"
	"github.com/policylabs/ampel/pkg/evaluator/class"
)

// Identity is the plugin's identity, what a policy names in its runtime to
// require the `ampel` object.
var Identity = class.MustParseIdentity("ampel@v0")

// VarName is the name of the variable the engine object is bound to.
const VarName = "ampel"

// Plugin wires the engine object into ampel's CEL evaluator.
type Plugin struct {
	Engine *Engine
}

// New returns a plugin describing the running binary.
func New() *Plugin {
	return &Plugin{Engine: FromBuild()}
}

// NewWithEngine returns a plugin describing the given engine, for an
// evaluator that knows more than the build does, and for tests.
func NewWithEngine(e *Engine) *Plugin {
	return &Plugin{Engine: e}
}

func (p *Plugin) Capabilities() []api.Capability {
	return []api.Capability{api.CapabilityEvalEnginePlugin}
}

func (p *Plugin) CanRegisterFor(c class.Class) bool {
	return c.Name() == "cel"
}

func (p *Plugin) Library() cel.EnvOption {
	return cel.Lib(p.Engine)
}

func (p *Plugin) VarValues(_ *papi.Policy, _ attestation.Subject, _ []attestation.Predicate) map[string]any {
	return map[string]any{
		VarName: p.Engine,
	}
}

func (p *Plugin) Identity() *class.Identity {
	return Identity
}
