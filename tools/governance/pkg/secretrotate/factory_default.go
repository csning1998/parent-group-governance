package secretrotate

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrServiceNotReady reports a service which answered no verification before ctx ended.
var ErrServiceNotReady = errors.New("secretrotate: the service answered no verification")

// AwaitFactoryDefault verifies the factory default every interval until the service answers, and reports whether the
// service still accepts the factory default. A false result means the service retains a rotated password.
func AwaitFactoryDefault(ctx context.Context, spec Spec, interval time.Duration) (bool, error) {
	if spec.FactoryDefaultPassword == "" {
		return false, errors.New("secretrotate: the spec declares no factory default password")
	}
	if err := requireVerify(spec); err != nil {
		return false, err
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		accepted, err := spec.Verify(ctx, spec.FactoryDefaultPassword)
		if err == nil {
			return accepted, nil
		}
		select {
		case <-ctx.Done():
			return false, fmt.Errorf("%w: %w", ErrServiceNotReady, err)
		case <-ticker.C:
		}
	}
}
