//go:build windows

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
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	var fileInfo syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(syscall.Handle(f.Fd()), &fileInfo); err != nil {
		return false, err
	}
	return fileInfo.NumberOfLinks > 1, nil
}
