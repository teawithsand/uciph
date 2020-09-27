package token

import (
	"errors"
	"time"
)

var ErrNoIssuedAt = errors.New("uciph/cutil/token: Token data does not contains CreatedAt")
var ErrTokenExpired = errors.New("uciph/cutil/token: Token data is expired")

// CreatedAtData is kind of token data, which contains time of creation of this token.
type CreatedAtData interface {
	GetIssuedAt() time.Time
}

// ExpireManager returns error if token is expired.
type ExpireManager struct {
	Manager // underlying manager, has to be provided

	Now            func() time.Time // defaults to time.Now
	ForceCreatedAt bool             // if false, then data that does not implement CreatedAtData interface, then it's skipped with no error.

	MaxTokenLifetime time.Duration                                               // Skipped if zero
	IsExpired        func(res interface{}, livesFor time.Duration) (bool, error) // Skipped if nil
}

// LoadToken loads token data using underlying manager, and chck
func (m *ExpireManager) LoadToken(token []byte) (res interface{}, err error) {
	res, err = m.Manager.LoadToken(token)
	if err != nil {
		return
	}
	var now time.Time
	if m.Now != nil {
		now = m.Now()
	} else {
		now = time.Now()
	}

	cad, ok := res.(CreatedAtData)
	if ok {
		createdAt := cad.GetIssuedAt()
		livesFor := now.Sub(createdAt)
		if livesFor < 0 { // back in time?
			livesFor = 0
		}

		if m.MaxTokenLifetime != 0 && livesFor > m.MaxTokenLifetime {
			err = &TokenLoadError{
				Err: ErrTokenExpired,
			}
			return
		}

		if m.IsExpired != nil {
			var expired bool
			expired, err = m.IsExpired(res, livesFor)
			if err != nil {
				return
			}
			if expired {
				err = &TokenLoadError{
					Err: ErrTokenExpired,
				}
			}
		}

	} else if m.ForceCreatedAt {
		err = &TokenLoadError{
			Err: ErrNoIssuedAt,
		}
		return
	}

	return
}
