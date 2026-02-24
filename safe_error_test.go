package workos

import (
	"errors"
	"testing"
)

func TestSafeErrorWrapsCause(t *testing.T) {
	cause := errors.New("internal detail")
	err := &SafeError{msg: "workos: safe message", cause: cause}

	if err.Error() != "workos: safe message" {
		t.Fatalf("Error() = %q", err.Error())
	}
	if !errors.Is(err, cause) {
		t.Fatal("errors.Is should match wrapped cause")
	}
	var target *SafeError
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match SafeError")
	}
}
