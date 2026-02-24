package workos

// SafeError wraps a cause with an error string safe for default logging.
type SafeError struct {
	msg   string
	cause error
}

func (e *SafeError) Error() string { return e.msg }
func (e *SafeError) Unwrap() error { return e.cause }
