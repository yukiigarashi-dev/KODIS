//go:build !unix

package audit

import (
	"errors"
	"os"
)

// lock fails closed where exclusive file locking is not implemented.
func lock(*os.File) error {
	return errors.New("audit log locking is only supported on unix")
}
