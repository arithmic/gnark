package sw_bw6761

import (
	"fmt"
	"math/big"

	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// G1Affine is the point in G1. It is an alias to the generic emulated affine
// point.
type G1Affine = sw_emulated.AffinePoint[BaseField]

// Scalar is the scalar in the groups. It is an alias to the emulated element
// defined over the scalar field of the groups.
type Scalar = emulated.Element[ScalarField]

// NewG1Affine allocates a witness from the native G1 element and returns it.
func NewG1Affine(v bw6761.G1Affine) G1Affine {
	return G1Affine{
		X: emulated.ValueOf[BaseField](v.X),
		Y: emulated.ValueOf[BaseField](v.Y),
	}
}

// NewScalar allocates a witness from the native scalar and returns it.
func NewScalar(v fr_bw6761.Element) Scalar {
	return emulated.ValueOf[ScalarField](v)
}

// ScalarField is the [emulated.FieldParams] implementation of the curve scalar field.
type ScalarField = emulated.BW6761Fr

// BaseField is the [emulated.FieldParams] implementation of the curve base field.
type BaseField = emulated.BW6761Fp

type G1 struct {
	curveF *emulated.Field[BaseField]
	w      *emulated.Element[BaseField]
}

func NewG1(api frontend.API) (*G1, error) {
	ba, err := emulated.NewField[BaseField](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	w := ba.NewElement("1968985824090209297278610739700577151397666382303825728450741611566800370218827257750865013421937292370006175842381275743914023380727582819905021229583192207421122272650305267822868639090213645505120388400344940985710520836292650")
	return &G1{
		curveF: ba,
		w:      w,
	}, nil
}

func (g1 *G1) phi(q *G1Affine) *G1Affine {
	x := g1.curveF.Mul(&q.X, g1.w)

	return &G1Affine{
		X: *x,
		Y: q.Y,
	}
}

func (g1 *G1) double(p *G1Affine) *G1Affine {
	// compute λ = (3p.x²)/2*p.y
	xx3a := g1.curveF.Mul(&p.X, &p.X)
	xx3a = g1.curveF.MulConst(xx3a, big.NewInt(3))
	y1 := g1.curveF.MulConst(&p.Y, big.NewInt(2))
	λ := g1.curveF.Div(xx3a, y1)

	// xr = λ²-2p.x
	mone := g1.curveF.NewElement(-1)
	xr := g1.curveF.Eval([][]*baseEl{{λ, λ}, {mone, &p.X}}, []int{1, 2})

	// yr = λ(p.x-xr) - p.y
	yr := g1.curveF.Eval([][]*baseEl{{λ, &p.X}, {mone, λ, xr}, {mone, &p.Y}}, []int{1, 1, 1})

	return &G1Affine{
		X: *xr,
		Y: *yr,
	}
}

func (g1 *G1) doubleN(p *G1Affine, n int) *G1Affine {
	pn := p
	for s := 0; s < n; s++ {
		pn = g1.double(pn)
	}
	return pn
}

func (g1 G1) add(p, q *G1Affine) *G1Affine {
	// compute λ = (q.y-p.y)/(q.x-p.x)
	qypy := g1.curveF.Sub(&q.Y, &p.Y)
	qxpx := g1.curveF.Sub(&q.X, &p.X)
	λ := g1.curveF.Div(qypy, qxpx)

	// xr = λ²-p.x-q.x
	mone := g1.curveF.NewElement(-1)
	xr := g1.curveF.Eval([][]*baseEl{{λ, λ}, {mone, &p.X}, {mone, &q.X}}, []int{1, 1, 1})

	// p.y = λ(p.x-r.x) - p.y
	yr := g1.curveF.Eval([][]*baseEl{{λ, &p.X}, {mone, λ, xr}, {mone, &p.Y}}, []int{1, 1, 1})

	return &G1Affine{
		X: *xr,
		Y: *yr,
	}
}

func (g1 G1) neg(p *G1Affine) *G1Affine {
	xr := &p.X
	yr := g1.curveF.Neg(&p.Y)
	return &G1Affine{
		X: *xr,
		Y: *yr,
	}
}

func (g1 G1) sub(p, q *G1Affine) *G1Affine {
	qNeg := g1.neg(q)
	return g1.add(p, qNeg)
}

func (g1 G1) doubleAndAdd(p, q *G1Affine) *G1Affine {

	// compute λ1 = (q.y-p.y)/(q.x-p.x)
	yqyp := g1.curveF.Sub(&q.Y, &p.Y)
	xqxp := g1.curveF.Sub(&q.X, &p.X)
	λ1 := g1.curveF.Div(yqyp, xqxp)

	// compute x2 = λ1²-p.x-q.x
	mone := g1.curveF.NewElement(-1)
	x2 := g1.curveF.Eval([][]*baseEl{{λ1, λ1}, {mone, &p.X}, {mone, &q.X}}, []int{1, 1, 1})

	// omit y1 computation
	// compute -λ1 = λ1+2*p.y/(x1-p.x)
	ypyp := g1.curveF.Add(&p.Y, &p.Y)
	x2xp := g1.curveF.Sub(x2, &p.X)
	λ2 := g1.curveF.Div(ypyp, x2xp)
	λ2 = g1.curveF.Add(λ1, λ2)

	// compute x3 = (-λ2)²-p.x-x3
	x3 := g1.curveF.Eval([][]*baseEl{{λ2, λ2}, {mone, &p.X}, {mone, x2}}, []int{1, 1, 1})

	// compute y3 = -λ2*(x3 - p.x)-p.y
	y3 := g1.curveF.Eval([][]*baseEl{{mone, λ2, &p.X}, {λ2, x3}, {mone, &p.Y}}, []int{1, 1, 1})

	return &G1Affine{
		X: *x3,
		Y: *y3,
	}
}

func (g1 G1) triple(p *G1Affine) *G1Affine {

	// compute λ = (3p.x²)/2*p.y
	xx := g1.curveF.Mul(&p.X, &p.X)
	xx = g1.curveF.MulConst(xx, big.NewInt(3))
	y2 := g1.curveF.MulConst(&p.Y, big.NewInt(2))
	λ1 := g1.curveF.Div(xx, y2)

	// xr = λ²-2p.x
	mone := g1.curveF.NewElement(-1)
	x2 := g1.curveF.Eval([][]*baseEl{{λ1, λ1}, {mone, &p.X}}, []int{1, 2})

	// omit y2 computation, and
	// compute λ2 = 2p.y/(x2 − p.x) − λ1.
	x1x2 := g1.curveF.Sub(&p.X, x2)
	λ2 := g1.curveF.Div(y2, x1x2)
	λ2 = g1.curveF.Sub(λ2, λ1)

	// xr = λ²-p.x-x2
	xr := g1.curveF.Eval([][]*baseEl{{λ2, λ2}, {mone, &p.X}, {mone, x2}}, []int{1, 1, 1})

	// yr = λ(p.x-xr) - p.y
	yr := g1.curveF.Eval([][]*baseEl{{λ2, &p.X}, {mone, λ2, xr}, {mone, &p.Y}}, []int{1, 1, 1})

	return &G1Affine{
		X: *xr,
		Y: *yr,
	}
}

// scalarMulBySeed computes the [x₀]q where x₀=9586122913090633729 is the seed of the curve.
func (g1 *G1) scalarMulBySeed(q *G1Affine) *G1Affine {
	z := g1.triple(q)
	z = g1.doubleAndAdd(z, q)
	t0 := g1.double(z)
	t0 = g1.double(t0)
	z = g1.add(z, t0)
	t1 := g1.triple(z)
	t0 = g1.add(t0, t1)
	t0 = g1.doubleN(t0, 9)
	z = g1.doubleAndAdd(t0, z)
	z = g1.doubleN(z, 45)
	z = g1.doubleAndAdd(z, q)

	return z
}
