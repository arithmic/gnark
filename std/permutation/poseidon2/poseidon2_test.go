package poseidon

import (
	"fmt"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	frbls24317 "github.com/consensys/gnark-crypto/ecc/bls24-317/fr"
	poseidonbls24317 "github.com/consensys/gnark-crypto/ecc/bls24-317/fr/poseidon2"

	frbls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	poseidonbls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr/poseidon2"

	frbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	poseidonbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/poseidon2"

	frbw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/fr"
	poseidonbw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/fr/poseidon2"

	frbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	poseidonbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/poseidon2"

	frbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	poseidonbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/poseidon2"

	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/frontend/cs/r1cs"
	"github.com/arithmic/gnark/test"
	frbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	poseidonbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	frgrumpkin "github.com/consensys/gnark-crypto/ecc/grumpkin/fr"

	poseidongrumpkin "github.com/consensys/gnark-crypto/ecc/grumpkin/fr/poseidon2"
)

type Poseidon2Circuit struct {
	Input  []frontend.Variable
	Output []frontend.Variable `gnark:",public"`
	params circuitParams
}

type circuitParams struct {
	rf int
	rp int
	t  int
	id ecc.ID
}

func (c *Poseidon2Circuit) Define(api frontend.API) error {
	h, err := NewPoseidon2FromParameters(api, c.params.t, c.params.rf, c.params.rp)
	if err != nil {
		return fmt.Errorf("could not create poseidon2 hasher: %w", err)
	}
	h.Permutation(c.Input)
	for i := 0; i < len(c.Input); i++ {
		api.AssertIsEqual(c.Output[i], c.Input[i])
	}
	return nil
}

// To Compute the number of constraints in the Poseidon2Circuit for GRUMPKIN
func TestPoseidon2CircuitConstraintsGRUMPKIN(t *testing.T) {
	// Define the circuit
	var circuit Poseidon2Circuit

	// Set circuit parameters
	params := circuitParams{rf: 8, rp: 56, t: 3, id: ecc.GRUMPKIN}
	circuit.params = params
	circuit.Input = make([]frontend.Variable, params.t)
	circuit.Output = make([]frontend.Variable, params.t)

	// // Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)

	// Print the number of constraints
	fmt.Printf("Circuit compiled in: %s\n", duration)
	fmt.Printf("Number of constraints in Poseidon2Circuit: %d\n", r1cs.GetNbConstraints())
}

// To Compute the number of constraints in the Poseidon2Circuit for BN254
func TestPoseidon2CircuitConstraintsBN254(t *testing.T) {
	// Define the circuit
	var circuit Poseidon2Circuit

	// Set circuit parameters
	params := circuitParams{rf: 8, rp: 56, t: 3, id: ecc.BN254}
	circuit.params = params
	circuit.Input = make([]frontend.Variable, params.t)
	circuit.Output = make([]frontend.Variable, params.t)

	// // Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)

	// Print the number of constraints
	fmt.Printf("Circuit compiled in: %s\n", duration)
	fmt.Printf("Number of constraints in Poseidon2Circuit: %d\n", r1cs.GetNbConstraints())
}

func TestPoseidon2(t *testing.T) {

	assert := test.NewAssert(t)

	params := make(map[ecc.ID]circuitParams)
	params[ecc.BN254] = circuitParams{rf: 8, rp: 56, t: 3, id: ecc.BN254}
	params[ecc.BLS12_381] = circuitParams{rf: 8, rp: 56, t: 3, id: ecc.BLS12_381}
	params[ecc.BLS12_377] = circuitParams{rf: 8, rp: 56, t: 3, id: ecc.BLS12_377}
	params[ecc.BW6_761] = circuitParams{rf: 8, rp: 56, t: 3, id: ecc.BW6_761}
	params[ecc.BW6_633] = circuitParams{rf: 8, rp: 56, t: 3, id: ecc.BW6_633}
	params[ecc.BLS24_315] = circuitParams{rf: 8, rp: 56, t: 3, id: ecc.BLS24_315}
	params[ecc.BLS24_317] = circuitParams{rf: 8, rp: 56, t: 3, id: ecc.BLS24_317}
	params[ecc.GRUMPKIN] = circuitParams{rf: 8, rp: 56, t: 3, id: ecc.GRUMPKIN}

	{
		var circuit, validWitness Poseidon2Circuit

		h := poseidonbn254.NewPermutation(
			params[ecc.BN254].t,
			params[ecc.BN254].rf,
			params[ecc.BN254].rp,
		)
		var in, out [3]frbn254.Element
		for i := 0; i < 3; i++ {
			in[i].SetRandom()
		}
		copy(out[:], in[:])
		err := h.Permutation(out[:])
		if err != nil {
			t.Fatal(err)
		}

		validWitness.Input = make([]frontend.Variable, 3)
		validWitness.Output = make([]frontend.Variable, 3)

		circuit.Input = make([]frontend.Variable, 3)
		circuit.Output = make([]frontend.Variable, 3)
		circuit.params = params[ecc.BN254]

		for i := 0; i < 3; i++ {
			validWitness.Input[i] = in[i].String()
			validWitness.Output[i] = out[i].String()
		}
		assert.CheckCircuit(&circuit,
			test.WithValidAssignment(&validWitness),
			test.WithCurves(ecc.BN254))
	}

	{
		var circuit, validWitness Poseidon2Circuit

		h := poseidongrumpkin.NewPermutation(
			params[ecc.GRUMPKIN].t,
			params[ecc.GRUMPKIN].rf,
			params[ecc.GRUMPKIN].rp,
		)
		var in, out [3]frgrumpkin.Element
		for i := 0; i < 3; i++ {
			in[i].SetRandom()
		}
		copy(out[:], in[:])
		err := h.Permutation(out[:])
		if err != nil {
			t.Fatal(err)
		}

		validWitness.Input = make([]frontend.Variable, 3)
		validWitness.Output = make([]frontend.Variable, 3)

		circuit.Input = make([]frontend.Variable, 3)
		circuit.Output = make([]frontend.Variable, 3)
		circuit.params = params[ecc.GRUMPKIN]

		for i := 0; i < 3; i++ {
			validWitness.Input[i] = in[i].String()
			validWitness.Output[i] = out[i].String()
		}
		assert.CheckCircuit(&circuit,
			test.WithValidAssignment(&validWitness),
			test.WithCurves(ecc.GRUMPKIN))
	}

	{
		var circuit, validWitness Poseidon2Circuit

		h := poseidonbls12377.NewPermutation(
			params[ecc.BLS12_377].t,
			params[ecc.BLS12_377].rf,
			params[ecc.BLS12_377].rp,
		)
		var in, out [3]frbls12377.Element
		for i := 0; i < 3; i++ {
			in[i].SetRandom()
		}
		copy(out[:], in[:])
		err := h.Permutation(out[:])
		if err != nil {
			t.Fatal(err)
		}

		validWitness.Input = make([]frontend.Variable, 3)
		validWitness.Output = make([]frontend.Variable, 3)

		circuit.Input = make([]frontend.Variable, 3)
		circuit.Output = make([]frontend.Variable, 3)
		circuit.params = params[ecc.BLS12_377]

		for i := 0; i < 3; i++ {
			validWitness.Input[i] = in[i].String()
			validWitness.Output[i] = out[i].String()
		}
		assert.CheckCircuit(&circuit,
			test.WithValidAssignment(&validWitness),
			test.WithCurves(ecc.BLS12_377))
	}
	{
		var circuit, validWitness Poseidon2Circuit

		h := poseidonbls12381.NewPermutation(
			params[ecc.BLS12_381].t,
			params[ecc.BLS12_381].rf,
			params[ecc.BLS12_381].rp,
		)
		var in, out [3]frbls12381.Element
		for i := 0; i < 3; i++ {
			in[i].SetRandom()
		}
		copy(out[:], in[:])
		err := h.Permutation(out[:])
		if err != nil {
			t.Fatal(err)
		}

		validWitness.Input = make([]frontend.Variable, 3)
		validWitness.Output = make([]frontend.Variable, 3)

		circuit.Input = make([]frontend.Variable, 3)
		circuit.Output = make([]frontend.Variable, 3)
		circuit.params = params[ecc.BLS12_381]

		for i := 0; i < 3; i++ {
			validWitness.Input[i] = in[i].String()
			validWitness.Output[i] = out[i].String()
		}
		assert.CheckCircuit(&circuit,
			test.WithValidAssignment(&validWitness),
			test.WithCurves(ecc.BLS12_381))
	}
	{
		var circuit, validWitness Poseidon2Circuit

		h := poseidonbw6633.NewPermutation(
			params[ecc.BW6_633].t,
			params[ecc.BW6_633].rf,
			params[ecc.BW6_633].rp,
		)
		var in, out [3]frbw6633.Element
		for i := 0; i < 3; i++ {
			in[i].SetRandom()
		}
		copy(out[:], in[:])
		err := h.Permutation(out[:])
		if err != nil {
			t.Fatal(err)
		}

		validWitness.Input = make([]frontend.Variable, 3)
		validWitness.Output = make([]frontend.Variable, 3)

		circuit.Input = make([]frontend.Variable, 3)
		circuit.Output = make([]frontend.Variable, 3)
		circuit.params = params[ecc.BW6_633]

		for i := 0; i < 3; i++ {
			validWitness.Input[i] = in[i].String()
			validWitness.Output[i] = out[i].String()
		}
		assert.CheckCircuit(&circuit,
			test.WithValidAssignment(&validWitness),
			test.WithCurves(ecc.BW6_633))
	}
	{
		var circuit, validWitness Poseidon2Circuit

		h := poseidonbw6633.NewPermutation(
			params[ecc.BW6_633].t,
			params[ecc.BW6_633].rf,
			params[ecc.BW6_633].rp,
		)
		var in, out [3]frbw6633.Element
		for i := 0; i < 3; i++ {
			in[i].SetRandom()
		}
		copy(out[:], in[:])
		err := h.Permutation(out[:])
		if err != nil {
			t.Fatal(err)
		}

		validWitness.Input = make([]frontend.Variable, 3)
		validWitness.Output = make([]frontend.Variable, 3)

		circuit.Input = make([]frontend.Variable, 3)
		circuit.Output = make([]frontend.Variable, 3)
		circuit.params = params[ecc.BW6_633]

		for i := 0; i < 3; i++ {
			validWitness.Input[i] = in[i].String()
			validWitness.Output[i] = out[i].String()
		}
		assert.CheckCircuit(&circuit,
			test.WithValidAssignment(&validWitness),
			test.WithCurves(ecc.BW6_633))
	}
	{
		var circuit, validWitness Poseidon2Circuit

		h := poseidonbw6761.NewPermutation(
			params[ecc.BW6_761].t,
			params[ecc.BW6_761].rf,
			params[ecc.BW6_761].rp,
		)
		var in, out [3]frbw6761.Element
		for i := 0; i < 3; i++ {
			in[i].SetRandom()
		}
		copy(out[:], in[:])
		err := h.Permutation(out[:])
		if err != nil {
			t.Fatal(err)
		}

		validWitness.Input = make([]frontend.Variable, 3)
		validWitness.Output = make([]frontend.Variable, 3)

		circuit.Input = make([]frontend.Variable, 3)
		circuit.Output = make([]frontend.Variable, 3)
		circuit.params = params[ecc.BW6_761]

		for i := 0; i < 3; i++ {
			validWitness.Input[i] = in[i].String()
			validWitness.Output[i] = out[i].String()
		}
		assert.CheckCircuit(&circuit,
			test.WithValidAssignment(&validWitness),
			test.WithCurves(ecc.BW6_761))
	}
	{
		var circuit, validWitness Poseidon2Circuit

		h := poseidonbls24315.NewPermutation(
			params[ecc.BLS24_315].t,
			params[ecc.BLS24_315].rf,
			params[ecc.BLS24_315].rp,
		)
		var in, out [3]frbls24315.Element
		for i := 0; i < 3; i++ {
			in[i].SetRandom()
		}
		copy(out[:], in[:])
		err := h.Permutation(out[:])
		if err != nil {
			t.Fatal(err)
		}

		validWitness.Input = make([]frontend.Variable, 3)
		validWitness.Output = make([]frontend.Variable, 3)

		circuit.Input = make([]frontend.Variable, 3)
		circuit.Output = make([]frontend.Variable, 3)
		circuit.params = params[ecc.BLS24_315]

		for i := 0; i < 3; i++ {
			validWitness.Input[i] = in[i].String()
			validWitness.Output[i] = out[i].String()
		}
		assert.CheckCircuit(&circuit,
			test.WithValidAssignment(&validWitness),
			test.WithCurves(ecc.BLS24_315))
	}
	{
		var circuit, validWitness Poseidon2Circuit

		h := poseidonbls24317.NewPermutation(
			params[ecc.BLS24_317].t,
			params[ecc.BLS24_317].rf,
			params[ecc.BLS24_317].rp,
		)
		var in, out [3]frbls24317.Element
		for i := 0; i < 3; i++ {
			in[i].SetRandom()
		}
		copy(out[:], in[:])
		err := h.Permutation(out[:])
		if err != nil {
			t.Fatal(err)
		}

		validWitness.Input = make([]frontend.Variable, 3)
		validWitness.Output = make([]frontend.Variable, 3)

		circuit.Input = make([]frontend.Variable, 3)
		circuit.Output = make([]frontend.Variable, 3)
		circuit.params = params[ecc.BLS24_317]

		for i := 0; i < 3; i++ {
			validWitness.Input[i] = in[i].String()
			validWitness.Output[i] = out[i].String()
		}
		assert.CheckCircuit(&circuit,
			test.WithValidAssignment(&validWitness),
			test.WithCurves(ecc.BLS24_317))
	}

}
