//go:build !linux

package logtail

import "os"

func inodeOf(os.FileInfo) uint64 { return 0 }
