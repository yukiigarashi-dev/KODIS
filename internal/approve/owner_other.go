//go:build !unix

package approve

import (
	"errors"
	"os"
)

// Key files are refused where symlink and ownership checks are unavailable.
var errUnsupported = errors.New("approver key files are only supported on unix")

func openNoFollow(string) (*os.File, error) { return nil, errUnsupported }

func checkOwner(os.FileInfo) error { return errUnsupported }
