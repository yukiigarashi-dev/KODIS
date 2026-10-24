//go:build unix

package approve

import (
	"fmt"
	"os"
	"syscall"
)

// openNoFollow refuses symlinks and does not block on FIFOs; the caller
// then rejects anything that is not a regular file.
func openNoFollow(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: %w (symlinks are refused)", path, err)
	}
	return f, nil
}

func checkOwner(fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine file owner")
	}
	if uid := os.Getuid(); int(st.Uid) != uid {
		return fmt.Errorf("owned by uid %d, not the current user (uid %d)", st.Uid, uid)
	}
	return nil
}
