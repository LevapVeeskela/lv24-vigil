//go:build !windows

package safepath

import (
	"os"
	"syscall"
)

// HasMultipleLinks reports whether path is a regular file with more than one
// hardlink. A hostile repository can hardlink a file outside the tree; writing
// through that path would modify the outside file even though the path itself
// looks confined.
func HasMultipleLinks(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, nil
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, nil
	}
	return stat.Nlink > 1, nil
}
