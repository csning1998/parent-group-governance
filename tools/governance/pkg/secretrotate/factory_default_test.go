package secretrotate

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAwaitFactoryDefault(t *testing.T) {
	unreachable := errors.New("example connection refused")
	tests := []struct {
		name      string
		answers   []error
		accepts   bool
		wantFresh bool
		wantErr   error
	}{
		{name: "fresh after the service starts", answers: []error{unreachable, unreachable, nil}, accepts: true, wantFresh: true},
		{name: "retained password", answers: []error{nil}, accepts: false, wantFresh: false},
		{name: "service never answers", answers: []error{unreachable}, wantErr: ErrServiceNotReady},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls int
			spec := Spec{
				FactoryDefaultPassword: "example-default",
				Verify: func(_ context.Context, secret string) (bool, error) {
					if secret != "example-default" {
						t.Errorf("Verify received %q, want the factory default", secret)
					}
					answer := tt.answers[min(calls, len(tt.answers)-1)]
					calls++
					if answer != nil {
						return false, answer
					}
					return tt.accepts, nil
				},
			}
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()

			fresh, err := AwaitFactoryDefault(ctx, spec, time.Millisecond)
			if !errors.Is(err, tt.wantErr) || fresh != tt.wantFresh {
				t.Errorf("AwaitFactoryDefault = %v, %v, want %v, %v", fresh, err, tt.wantFresh, tt.wantErr)
			}
		})
	}
}

func TestAwaitFactoryDefault_RequiresAFactoryDefault(t *testing.T) {
	spec := Spec{Verify: func(context.Context, string) (bool, error) { return true, nil }}
	if _, err := AwaitFactoryDefault(context.Background(), spec, time.Millisecond); err == nil {
		t.Error("AwaitFactoryDefault succeeded without a factory default")
	}
}

func TestAwaitFactoryDefault_RequiresAVerification(t *testing.T) {
	spec := Spec{FactoryDefaultPassword: "example-default"}
	if _, err := AwaitFactoryDefault(context.Background(), spec, time.Millisecond); err == nil {
		t.Error("AwaitFactoryDefault succeeded without a verification")
	}
}
