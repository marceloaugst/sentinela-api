//go:build !linux

package collector

type inodeInfo struct {
	mount string
	pct   float64
}

func inodeUsage(string) []inodeInfo { return nil }
