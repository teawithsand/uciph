// Package pow implements proof of work algorithms.
package pow

import "context"

// Gen Generates POW challenges.
// Usually it has Checker attached to it.
type Gen interface {
	GenChal(options interface{}, appendTo []byte) (res []byte, err error)
}

// GenFunc is function, which is Gen.
type GenFunc func(options interface{}, appendTo []byte) (res []byte, err error)

// GenChal makes GenFunc satisfy Gen.
func (f GenFunc) GenChal(options interface{}, appendTo []byte) (res []byte, err error) {
	return f(options, appendTo)
}

// Solver is able to solve challenges.
// It respects timeout according to context argument.
type Solver interface {
	SolveChal(ctx context.Context, options interface{}, challenge, appendTo []byte) (res []byte, err error)
}

// SolverFunc is function, which is valid Solver.
type SolverFunc func(ctx context.Context, options interface{}, challenge, appendTo []byte) (res []byte, err error)

// SolveChal makes SolverFunc satisfy Solver.
func (f SolverFunc) SolveChal(ctx context.Context, options interface{}, challenge, appendTo []byte) (res []byte, err error) {
	return f(ctx, options, challenge, appendTo)
}

// Checker checks if challenge solution is valid or not.
//
// Note: checker DOES NOT HAVE TO check if given challenge has been created by corresponding generator.
// It's caller responsibility to ensure that.
type Checker interface {
	CheckChal(options interface{}, challenge, solution []byte) (err error)
}

// CheckerFunc is function, which is valid Checker.
type CheckerFunc func(options interface{}, challenge, solution []byte) (err error)

// CheckChal makes CheckerFunc satisfy Checker.
func (f CheckerFunc) CheckChal(options interface{}, challenge, solution []byte) (err error) {
	return f(options, challenge, solution)
}
