package collector

import (
	"math"
	"testing"
)

func TestParseCPUStatAndUsage(t *testing.T) {
	a, err := ParseCPUStat("cpu  100 0 100 700 100 0 0 0 50 0\ncpu0 1 1 1 1 1 0 0 0 0 0\n")
	if err != nil {
		t.Fatal(err)
	}
	// total = 100+0+100+700+100 = 1000 (guest fora); idle = 700+100
	if a.Total != 1000 || a.Idle != 800 {
		t.Errorf("%+v", a)
	}
	b, _ := ParseCPUStat("cpu  200 0 200 1400 200 0 0 0 0 0\n")
	u, ok := CPUUsage(a, b)
	// delta total 1000, delta idle 800 => 20%
	if !ok || math.Abs(u-20) > 1e-9 {
		t.Errorf("uso = %v ok=%v", u, ok)
	}
	if _, ok := CPUUsage(b, a); ok {
		t.Error("contador regressivo deve ser inválido")
	}
	if _, ok := CPUUsage(a, a); ok {
		t.Error("intervalo zero deve ser inválido")
	}
	if _, err := ParseCPUStat("intr 1 2 3"); err == nil {
		t.Error("sem linha cpu deveria falhar")
	}
}

const meminfo = `MemTotal:        8000000 kB
MemFree:          500000 kB
MemAvailable:    6000000 kB
Buffers:          100000 kB
Cached:          5000000 kB
SwapTotal:       2000000 kB
SwapFree:        1500000 kB
`

func TestParseMeminfoUsedExcludesCache(t *testing.T) {
	m, err := ParseMeminfo(meminfo)
	if err != nil {
		t.Fatal(err)
	}
	if m.TotalBytes != 8000000*1024 || m.AvailableBytes != 6000000*1024 {
		t.Errorf("%+v", m)
	}
	// usada = total - disponível (cache NÃO conta como usado)
	if m.UsedBytes != 2000000*1024 {
		t.Errorf("usada = %d", m.UsedBytes)
	}
	if m.SwapTotalBytes != 2000000*1024 || m.SwapUsedBytes != 500000*1024 {
		t.Errorf("swap: %+v", m)
	}
}

func TestParseMeminfoFallbackAndErrors(t *testing.T) {
	m, err := ParseMeminfo("MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 50 kB\nCached: 150 kB\n")
	if err != nil || m.AvailableBytes != 300*1024 || m.UsedBytes != 700*1024 {
		t.Errorf("fallback sem MemAvailable: %+v %v", m, err)
	}
	if _, err := ParseMeminfo("MemFree: 1 kB"); err == nil {
		t.Error("sem MemTotal deveria falhar")
	}
}

func TestParseLoadavgUptime(t *testing.T) {
	l, err := ParseLoadavg("0.52 0.40 0.30 1/234 5678\n")
	if err != nil || l.M1 != 0.52 || l.M5 != 0.40 || l.M15 != 0.30 {
		t.Errorf("%+v %v", l, err)
	}
	if _, err := ParseLoadavg("x"); err == nil {
		t.Error("deveria falhar")
	}
	u, err := ParseUptime("12345.67 9999.00\n")
	if err != nil || u != 12345 {
		t.Errorf("%d %v", u, err)
	}
	if _, err := ParseUptime(""); err == nil {
		t.Error("deveria falhar")
	}
}

const netdev = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 999999 10 0 0 0 0 0 0 999999 10 0 0 0 0 0 0
  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0
  ens3: 500 5 0 0 0 0 0 0 700 7 0 0 0 0 0 0
docker0: 123456 1 0 0 0 0 0 0 654321 1 0 0 0 0 0 0
vethabc: 5 1 0 0 0 0 0 0 5 1 0 0 0 0 0 0
`

func TestParseNetDevIgnoresVirtual(t *testing.T) {
	rx, tx, ok := ParseNetDev(netdev)
	if !ok || rx != 1500 || tx != 2700 {
		t.Errorf("rx=%d tx=%d ok=%v", rx, tx, ok)
	}
	if _, _, ok := ParseNetDev("    lo: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\n"); ok {
		t.Error("somente loopback => sem interface elegível")
	}
}

const mounts = `sysfs /sys sysfs rw 0 0
proc /proc proc rw 0 0
/dev/sda1 / ext4 rw,relatime 0 0
tmpfs /run tmpfs rw 0 0
/dev/sda1 /var/lib/docker/overlay2/x ext4 rw 0 0
/dev/sdb1 /mnt/dados\040extra xfs rw 0 0
/dev/sdb1 /mnt/dados xfs rw 0 0
/dev/loop0 /snap/core/1 squashfs ro 0 0
overlay /var/lib/docker/overlay2/y overlay rw 0 0
tank/data /tank zfs rw 0 0
/dev/nvme0n1p1 /boot/efi vfat rw 0 0
`

func TestParseMounts(t *testing.T) {
	got := ParseMounts(mounts, 64)
	want := map[string]bool{"/": true, "/mnt/dados": true, "/tank": true, "/boot/efi": true}
	if len(got) != len(want) {
		t.Fatalf("volumes: %+v", got)
	}
	for _, m := range got {
		if !want[m.MountPoint] {
			t.Errorf("volume inesperado: %+v", m)
		}
	}
	if limited := ParseMounts(mounts, 2); len(limited) != 2 {
		t.Errorf("limite de volumes: %d", len(limited))
	}
}

func TestUnescapeMount(t *testing.T) {
	if got := unescapeMount(`/mnt/a\040b`); got != "/mnt/a b" {
		t.Errorf("%q", got)
	}
	if got := unescapeMount(`/x\04`); got != `/x\04` {
		t.Errorf("sequência incompleta deve ser preservada: %q", got)
	}
}

func TestParseOSRelease(t *testing.T) {
	n, v := ParseOSRelease("PRETTY_NAME=\"Ubuntu 24.04 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\n")
	if n != "Ubuntu" || v != "24.04" {
		t.Errorf("%q %q", n, v)
	}
}
