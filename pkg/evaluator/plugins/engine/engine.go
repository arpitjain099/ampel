// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

// Package engine provides the `ampel` object policies read the verifier
// engine's own data from: its version, when the run started, the runtime
// evaluating the policy and the plugins it loaded. Its methods let a policy
// say when it applies, as in `when: ampel.atLeast('v1.4.0')`, so a
// conformance policy written for a newer engine can skip on an older one.
package engine

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	msemver "github.com/Masterminds/semver/v3"
	"sigs.k8s.io/release-utils/version"
)

// Engine is what the verifier engine says about itself. It is the value
// bound to the `ampel` variable, and the receiver of its methods.
type Engine struct {
	// Version is the engine's version as the build stamped it, "v1.4.1".
	// A build from source has none and reads as a development build, which
	// every comparison treats as newer than any release.
	Version string
	// Started is when the verification run started.
	Started time.Time
	// Runtime is the identity of the runtime evaluating the policy, as in
	// "cel@v0".
	Runtime string
	// Plugins are the identities of the plugins the runtime loaded, as in
	// "semver@v0".
	Plugins []string
}

// FromBuild returns the engine of the running binary: its stamped version,
// starting now. The runtime and plugins are set by the evaluator that
// loads it.
func FromBuild() *Engine {
	return &Engine{Version: version.GetVersionInfo().GitVersion, Started: time.Now()}
}

// Development reports whether the engine was built from source, without a
// stamped release version.
func (e *Engine) Development() bool {
	_, ok := e.release()
	return !ok
}

// release parses the engine's version, reporting false for a development
// build, whose version is not a release.
func (e *Engine) release() (*msemver.Version, bool) {
	if e == nil || e.Version == "" {
		return nil, false
	}
	v, err := msemver.NewVersion(e.Version)
	if err != nil {
		return nil, false
	}
	return v, true
}

// NewerThan reports whether the engine is newer than the version. A
// development build is newer than anything.
func (e *Engine) NewerThan(v string) (bool, error) {
	return e.compare(v, func(c int) bool { return c > 0 })
}

// OlderThan reports whether the engine is older than the version. A
// development build is older than nothing.
func (e *Engine) OlderThan(v string) (bool, error) {
	return e.compare(v, func(c int) bool { return c < 0 })
}

// AtLeast reports whether the engine is the version or newer.
func (e *Engine) AtLeast(v string) (bool, error) {
	return e.compare(v, func(c int) bool { return c >= 0 })
}

// compare parses v and applies test to how the engine compares to it.
func (e *Engine) compare(v string, test func(int) bool) (bool, error) {
	other, err := msemver.NewVersion(v)
	if err != nil {
		return false, fmt.Errorf("parsing version %q: %w", v, err)
	}
	own, ok := e.release()
	if !ok {
		// A development build is newer than any release.
		return test(1), nil
	}
	return test(own.Compare(other)), nil
}

// Satisfies reports whether the engine's version satisfies the constraint,
// as in ">= 1.4, < 2". A development build satisfies any constraint.
func (e *Engine) Satisfies(constraint string) (bool, error) {
	c, err := msemver.NewConstraint(constraint)
	if err != nil {
		return false, fmt.Errorf("parsing constraint %q: %w", constraint, err)
	}
	own, ok := e.release()
	if !ok {
		return true, nil
	}
	return c.Check(own), nil
}

// HasPlugin reports whether the runtime loaded the plugin, named with or
// without its version: "semver" matches any version, "semver@v0" that one.
func (e *Engine) HasPlugin(name string) bool {
	for _, id := range e.Plugins {
		if id == name {
			return true
		}
		if base, _, _ := strings.Cut(id, "@"); base == name {
			return true
		}
	}
	return false
}

// EngineType is the CEL object type of the `ampel` variable. Like the other
// plugin objects it is an opaque handle the compiler dispatches methods on;
// unlike them, the value carries the data the methods answer from.
var EngineType = cel.ObjectType("ampel", traits.ReceiverType)

// Functions registers the methods of the `ampel` object.
func (e *Engine) Functions() []cel.EnvOption {
	return []cel.EnvOption{
		// Data.
		memberFn("version", cel.StringType, func(e *Engine) ref.Val { return types.String(e.Version) }),
		memberFn("started", cel.TimestampType, func(e *Engine) ref.Val { return types.Timestamp{Time: e.Started} }),
		memberFn("runtime", cel.StringType, func(e *Engine) ref.Val { return types.String(e.Runtime) }),
		memberFn("plugins", cel.ListType(cel.StringType), func(e *Engine) ref.Val {
			return types.DefaultTypeAdapter.NativeToValue(slices.Clone(e.Plugins))
		}),
		memberFn("development", cel.BoolType, func(e *Engine) ref.Val { return types.Bool(e.Development()) }),
		// Version comparisons.
		memberStringBoolFn("newerThan", (*Engine).NewerThan),
		memberStringBoolFn("olderThan", (*Engine).OlderThan),
		memberStringBoolFn("atLeast", (*Engine).AtLeast),
		memberStringBoolFn("satisfies", (*Engine).Satisfies),
		memberStringBoolFn("hasPlugin", func(e *Engine, name string) (bool, error) { return e.HasPlugin(name), nil }),
	}
}

// memberFn declares a method with no argument on the engine.
func memberFn(name string, ret *cel.Type, fn func(*Engine) ref.Val) cel.EnvOption {
	return cel.Function(name, cel.MemberOverload(
		"ampel_"+name+"_binding", []*cel.Type{EngineType}, ret,
		cel.UnaryBinding(func(self ref.Val) ref.Val {
			e, err := receiver(self)
			if err != nil {
				return types.NewErrFromString(err.Error())
			}
			return fn(e)
		}),
	))
}

// memberStringBoolFn declares a method taking a string and answering a bool.
func memberStringBoolFn(name string, fn func(*Engine, string) (bool, error)) cel.EnvOption {
	return cel.Function(name, cel.MemberOverload(
		"ampel_"+name+"_binding", []*cel.Type{EngineType, cel.StringType}, cel.BoolType,
		cel.BinaryBinding(func(self, arg ref.Val) ref.Val {
			e, err := receiver(self)
			if err != nil {
				return types.NewErrFromString(err.Error())
			}
			s, ok := arg.Value().(string)
			if !ok {
				return types.NewErrFromString(fmt.Sprintf("ampel.%s: argument must be a string, got %T", name, arg.Value()))
			}
			out, err := fn(e, s)
			if err != nil {
				return types.NewErrFromString("ampel." + name + ": " + err.Error())
			}
			return types.Bool(out)
		}),
	))
}

// receiver reads the engine out of the method's receiver.
func receiver(self ref.Val) (*Engine, error) {
	switch e := self.Value().(type) {
	case *Engine:
		return e, nil
	case Engine:
		return &e, nil
	default:
		return nil, fmt.Errorf("ampel: receiver is %T, not the engine", self.Value())
	}
}

// ---- ref.Val -------------------------------------------------------------

// ConvertToType converts the engine to the CEL type, which only its own
// type and the type type allow.
func (e *Engine) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case EngineType:
		return e
	case types.TypeType:
		return EngineType
	}
	return types.NewErr("type conversion error from '%s' to '%s'", EngineType, typeVal)
}

// Type returns the CEL type of the engine.
func (*Engine) Type() ref.Type { return EngineType }

// Equal compares two engines by value.
func (e *Engine) Equal(other ref.Val) ref.Val {
	o, ok := other.Value().(*Engine)
	if !ok {
		return types.False
	}
	return types.Bool(e.Version == o.Version && e.Started.Equal(o.Started) && e.Runtime == o.Runtime && slices.Equal(e.Plugins, o.Plugins))
}

// Value returns the engine itself.
func (e *Engine) Value() any { return e }

// ConvertToNative converts the engine to the Go type, which only its own
// allows.
func (e *Engine) ConvertToNative(typeDesc reflect.Type) (any, error) {
	if typeDesc == reflect.TypeOf(e) {
		return e, nil
	}
	return nil, fmt.Errorf("unsupported native conversion from ampel engine to %v", typeDesc)
}

// TypeAdapter turns an Engine passed by value into its CEL value.
type TypeAdapter struct{}

// NativeToValue adapts an Engine by value; everything else goes to the
// default adapter, which passes an *Engine through as the ref.Val it is.
func (TypeAdapter) NativeToValue(value any) ref.Val {
	if val, ok := value.(Engine); ok {
		return &val
	}
	return types.DefaultTypeAdapter.NativeToValue(value)
}

// CompileOptions declares the `ampel` type, variable and methods, which is
// what makes the engine a cel.Library.
func (e *Engine) CompileOptions() []cel.EnvOption {
	funcs := e.Functions()
	ret := make([]cel.EnvOption, 0, 3+len(funcs))
	ret = append(ret,
		cel.Types(EngineType),
		cel.CustomTypeAdapter(&TypeAdapter{}),
		cel.Variable("ampel", EngineType),
	)
	return append(ret, funcs...)
}

// ProgramOptions has nothing to add.
func (*Engine) ProgramOptions() []cel.ProgramOption { return nil }
