package netguard

import (
	"errors"
	"io"
)

// ErrResponseTooLarge is returned by a LimitedBody read once the body has
// more bytes than allowed. The bytes up to the cap may have been returned
// already; callers must treat the whole response as failed.
var ErrResponseTooLarge = errors.New("netguard: response body exceeds the size limit")

// LimitedBody wraps rc so that reading more than maxBytes fails with
// ErrResponseTooLarge (instead of silently truncating like
// io.LimitReader). Close closes rc. The guard's transport applies it to
// every response with Options.MaxResponseBytes; use it directly for other
// readers that need the same bound.
func LimitedBody(rc io.ReadCloser, maxBytes int64) io.ReadCloser {
	return &limitedBody{rc: rc, left: maxBytes}
}

type limitedBody struct {
	rc   io.ReadCloser
	left int64 // bytes still allowed
	err  error // sticky ErrResponseTooLarge
}

func (l *limitedBody) Read(p []byte) (int, error) {
	if l.err != nil {
		return 0, l.err
	}
	// Read one byte past the allowance so an over-long body is detected
	// even when it ends exactly one byte late.
	if int64(len(p)) > l.left+1 {
		p = p[:l.left+1]
	}
	n, err := l.rc.Read(p)
	if int64(n) > l.left {
		n = int(l.left)
		l.left = 0
		l.err = ErrResponseTooLarge
		return n, l.err
	}
	l.left -= int64(n)
	return n, err
}

func (l *limitedBody) Close() error { return l.rc.Close() }
