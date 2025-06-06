// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package test

import (
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/frontend/schema"
	gnarkio "github.com/consensys/gnark/io"
	"github.com/stretchr/testify/require"
)

var (
	ErrCompilationNotDeterministic = errors.New("compilation is not deterministic")
	ErrInvalidWitnessSolvedCS      = errors.New("invalid witness solved the constraint system")
	ErrInvalidWitnessVerified      = errors.New("invalid witness resulted in a valid proof")
)

// Assert is a helper to test circuits
type Assert struct {
	t *testing.T
	*require.Assertions
}

// NewAssert returns an Assert helper embedding a testify/require object for convenience
//
// The Assert object caches the compiled circuit:
//
// the first call to assert.ProverSucceeded/Failed will compile the circuit for n curves, m backends
// and subsequent calls will re-use the result of the compilation, if available.
func NewAssert(t *testing.T) *Assert {
	return &Assert{t: t, Assertions: require.New(t)}
}

// Run runs the test function fn as a subtest. The subtest is parametrized by
// the description strings descs.
func (a *Assert) Run(fn func(assert *Assert), descs ...string) {
	desc := strings.Join(descs, "/")
	a.t.Run(desc, func(t *testing.T) {
		assert := &Assert{t, require.New(t)}
		fn(assert)
	})
}

// Log logs using the test instance logger.
func (assert *Assert) Log(v ...interface{}) {
	assert.t.Log(v...)
}

// ProverSucceeded is deprecated: use [Assert.CheckCircuit] instead
func (assert *Assert) ProverSucceeded(circuit frontend.Circuit, validAssignment frontend.Circuit, opts ...TestingOption) {
	// copy the options
	newOpts := make([]TestingOption, len(opts), len(opts)+2)
	copy(newOpts, opts)
	newOpts = append(newOpts, WithValidAssignment(validAssignment))

	assert.CheckCircuit(circuit, newOpts...)
}

// ProverFailed is deprecated use [Assert.CheckCircuit] instead
func (assert *Assert) ProverFailed(circuit frontend.Circuit, invalidAssignment frontend.Circuit, opts ...TestingOption) {
	// copy the options
	newOpts := make([]TestingOption, len(opts), len(opts)+2)
	copy(newOpts, opts)
	newOpts = append(newOpts, WithInvalidAssignment(invalidAssignment))

	assert.CheckCircuit(circuit, newOpts...)
}

// SolvingSucceeded is deprecated: use [Assert.CheckCircuit] instead
func (assert *Assert) SolvingSucceeded(circuit frontend.Circuit, validWitness frontend.Circuit, opts ...TestingOption) {

	// copy the options
	newOpts := make([]TestingOption, len(opts), len(opts)+1)
	copy(newOpts, opts)
	newOpts = append(newOpts, WithValidAssignment(validWitness))

	assert.CheckCircuit(circuit, newOpts...)
}

// SolvingFailed is deprecated: use CheckCircuit instead
func (assert *Assert) SolvingFailed(circuit frontend.Circuit, invalidWitness frontend.Circuit, opts ...TestingOption) {
	// copy the options
	newOpts := make([]TestingOption, len(opts), len(opts)+1)
	copy(newOpts, opts)
	newOpts = append(newOpts, WithInvalidAssignment(invalidWitness))

	assert.CheckCircuit(circuit, newOpts...)
}

func lazySchema(field *big.Int, circuit frontend.Circuit) func() *schema.Schema {
	return func() *schema.Schema {
		// we only parse the schema if we need to display the witness in json.
		s, err := schema.New(field, circuit, tVariable)
		if err != nil {
			panic("couldn't parse schema from circuit: " + err.Error())
		}
		return s
	}
}

// compile the given circuit for given curve and backend, if not already present in cache
func (assert *Assert) compile(circuit frontend.Circuit, curveID ecc.ID, backendID backend.ID, compileOpts []frontend.CompileOption) (constraint.ConstraintSystem, error) {
	var newBuilder frontend.NewBuilder

	switch backendID {
	case backend.GROTH16:
		newBuilder = r1cs.NewBuilder
	case backend.PLONK:
		newBuilder = scs.NewBuilder
	default:
		panic("not implemented")
	}

	// else compile it and ensure it is deterministic
	ccs, err := frontend.Compile(curveID.ScalarField(), newBuilder, circuit, compileOpts...)
	if err != nil {
		return nil, err
	}

	_ccs, err := frontend.Compile(curveID.ScalarField(), newBuilder, circuit, compileOpts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCompilationNotDeterministic, err)
	}

	if !reflect.DeepEqual(ccs, _ccs) {
		return nil, ErrCompilationNotDeterministic
	}

	return ccs, nil
}

// error ensure the error is set, else fails the test
// add a witness to the error message if provided
func (assert *Assert) error(field *big.Int, err error, w *_witness) {
	if err != nil {
		return
	}
	json := "<nil>"
	if w != nil {
		bjson, err := w.full.ToJSON(lazySchema(field, w.assignment)())
		if err != nil {
			json = err.Error()
		} else {
			json = string(bjson)
		}
	}

	e := fmt.Errorf("did not error (but should have)\nwitness:%s", json)
	assert.FailNow(e.Error())
}

// ensure the error is nil, else fails the test
// add a witness to the error message if provided
func (assert *Assert) noError(field *big.Int, err error, w *_witness) {
	if err == nil {
		return
	}

	e := err

	if w != nil {
		var json string
		bjson, err := w.full.ToJSON(lazySchema(field, w.assignment)())
		if err != nil {
			json = err.Error()
		} else {
			json = string(bjson)
		}
		e = fmt.Errorf("%w\nwitness:%s", e, json)
	}

	assert.FailNow(e.Error())
}

func (assert *Assert) marshalWitnessJSON(w witness.Witness, s *schema.Schema, curveID ecc.ID, publicOnly bool) {
	var err error
	if publicOnly {
		w, err = w.Public()
		assert.NoError(err)
	}

	// serialize the vector to binary
	data, err := w.ToJSON(s)
	assert.NoError(err)

	// re-read
	witness, err := witness.New(curveID.ScalarField())
	assert.NoError(err)
	err = witness.FromJSON(s, data)
	assert.NoError(err)

	witnessMatch := reflect.DeepEqual(w, witness)
	assert.True(witnessMatch, "round trip marshaling failed")
}

func (assert *Assert) roundTripCheck(from any, builder func() any, descs ...string) {
	assert.Run(func(assert *Assert) {
		assert.NoError(gnarkio.RoundTripCheck(from, builder))
	}, descs...)
}
