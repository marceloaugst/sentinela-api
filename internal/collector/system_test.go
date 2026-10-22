package collector

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sentinela/internal/sysmetrics"
)

func TestParseVmstatOOM(t *testing.T) {
	n, ok := ParseVmstatOOM("nr_free_pages 100\noom_kill 7\npgfault 5\n")
	if !ok || n != 7 {
		t.Errorf("%d %v", n, ok)
	}
	if _, ok := ParseVmstatOOM("nr_free_pages 100\n"); ok {
		t.Error("sem oom_kill deveria ser ok=false")
	}
}

func TestParseDiskstatsKeepsOnlyWholeDisks(t *testing.T) {
	in := `   8       0 sda 100 0 0 500 50 0 0 300 0 0 0
   8       1 sda1 90 0 0 400 40 0 0 200 0 0 0
 259       0 nvme0n1 10 0 0 20 10 0 0 40 0 0 0
 259       1 nvme0n1p1 10 0 0 20 10 0 0 40 0 0 0
   7       0 loop0 5 0 0 5 0 0 0 0 0 0 0
 252       0 dm-0 5 0 0 5 0 0 0 0 0 0 0
`
	got := ParseDiskstats(in)
	if len(got) != 2 || got["sda"] != (DiskStat{Ops: 150, TimeMS: 800}) || got["nvme0n1"].Ops != 20 {
		t.Errorf("%+v", got)
	}
	if ms, ok := DiskLatencyMS(DiskStat{Ops: 100, TimeMS: 400}, DiskStat{Ops: 150, TimeMS: 800}); !ok || ms != 8 {
		t.Errorf("latência %v %v", ms, ok)
	}
	if _, ok := DiskLatencyMS(DiskStat{Ops: 5, TimeMS: 5}, DiskStat{Ops: 5, TimeMS: 9}); ok {
		t.Error("sem operações novas não há latência")
	}
}

func TestParseSecurityUpdates(t *testing.T) {
	n, ok := ParseSecurityUpdates("12 updates can be applied immediately.\n3 of these updates are standard security updates.\n")
	if !ok || n != 3 {
		t.Errorf("%d %v", n, ok)
	}
	if n, ok := ParseSecurityUpdates("5 updates can be applied immediately.\n"); !ok || n != 0 {
		t.Errorf("sem segurança: %d %v", n, ok)
	}
	if _, ok := ParseSecurityUpdates("lixo"); ok {
		t.Error("formato desconhecido")
	}
}

func testCert(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"}, NotBefore: notAfter.Add(-90 * 24 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCertDaysLeft(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	d, ok := CertDaysLeft(testCert(t, now.Add(5*24*time.Hour)), now)
	if !ok || d < 4.99 || d > 5.01 {
		t.Errorf("%v %v", d, ok)
	}
	if d, _ := CertDaysLeft(testCert(t, now.Add(-2*24*time.Hour)), now); d > -1.99 {
		t.Errorf("vencido deve ser negativo: %v", d)
	}
	if _, ok := CertDaysLeft([]byte("nada"), now); ok {
		t.Error("PEM inválido")
	}
}

func TestSystemCollectorDeltasAndFiles(t *testing.T) {
	dir := t.TempDir()
	proc := filepath.Join(dir, "proc")
	os.MkdirAll(proc, 0o755)
	write := func(p, s string) { os.MkdirAll(filepath.Dir(p), 0o755); os.WriteFile(p, []byte(s), 0o644) }
	write(filepath.Join(proc, "vmstat"), "oom_kill 3\n")
	write(filepath.Join(proc, "diskstats"), "8 0 sda 100 0 0 400 0 0 0 0 0 0 0\n")
	write(filepath.Join(dir, "updates"), "2 of these updates are standard security updates.\n")
	write(filepath.Join(dir, "certs", "site.exemplo.com.pem"), string(testCert(t, time.Now().Add(3*24*time.Hour))))
	sync := filepath.Join(dir, "timesync", "synchronized")
	os.MkdirAll(filepath.Dir(sync), 0o755) // diretório existe, arquivo não: não sincronizado

	c := &SystemCollector{ProcRoot: proc, CertGlobs: []string{filepath.Join(dir, "certs", "*.pem")}, UpdatesFile: filepath.Join(dir, "updates"), TimesyncFile: sync}
	now := time.Now()
	by := func(s []sysmetrics.Sample) map[string]float64 {
		m := map[string]float64{}
		for _, x := range s {
			m[x.Metric+"|"+x.Subject] = x.Value
		}
		return m
	}
	first := by(c.Collect(now))
	if _, ok := first["oom_kills|"]; ok {
		t.Error("a primeira leitura é só a base: não pode informar OOM")
	}
	if first["ntp_unsynchronized|"] != 1 || first["security_updates|"] != 2 || first["cert_days_left|site.exemplo.com"] < 2.9 {
		t.Errorf("primeira rodada: %v", first)
	}
	write(filepath.Join(proc, "vmstat"), "oom_kill 5\n")
	write(filepath.Join(proc, "diskstats"), "8 0 sda 110 0 0 500 0 0 0 0 0 0 0\n")
	write(sync, "")
	second := by(c.Collect(now.Add(time.Minute)))
	if second["oom_kills|"] != 2 || second["disk_latency_ms|sda"] != 10 || second["ntp_unsynchronized|"] != 0 {
		t.Errorf("segunda rodada: %v", second)
	}
}
