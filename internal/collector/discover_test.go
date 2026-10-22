package collector

import (
	"os"
	"path/filepath"
	"testing"

	"sentinela/internal/discovery"
)

type fakeHost struct {
	t    *testing.T
	root string
}

func newFakeHost(t *testing.T) (*fakeHost, *Discoverer) {
	root := t.TempDir()
	d := &Discoverer{
		CgroupRoot: filepath.Join(root, "cgroup"),
		ProcRoot:   filepath.Join(root, "proc"),
		UnitDirs:   []string{filepath.Join(root, "units")},
		UFWConf:    filepath.Join(root, "ufw.conf"),
	}
	h := &fakeHost{t: t, root: root}
	h.mkdir(filepath.Join(d.CgroupRoot, "system.slice"))
	h.mkdir(d.ProcRoot)
	h.mkdir(d.UnitDirs[0])
	return h, d
}

func (h *fakeHost) mkdir(p string) {
	h.t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		h.t.Fatal(err)
	}
}

func (h *fakeHost) write(p, content string) {
	h.t.Helper()
	h.mkdir(filepath.Dir(p))
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *fakeHost) proc(d *Discoverer, pid, comm, cgroup, cmdline string) {
	dir := filepath.Join(d.ProcRoot, pid)
	h.write(filepath.Join(dir, "comm"), comm+"\n")
	h.write(filepath.Join(dir, "cgroup"), cgroup+"\n")
	h.write(filepath.Join(dir, "cmdline"), cmdline)
}

func byKey(fs []discovery.Finding) map[string]discovery.Finding {
	m := map[string]discovery.Finding{}
	for _, f := range fs {
		m[f.Key] = f
	}
	return m
}

func TestDiscoverEmptyHost(t *testing.T) {
	_, d := newFakeHost(t)
	got := d.Discover()
	if len(got) != len(discovery.Catalog) {
		t.Fatalf("esperava %d itens, veio %d", len(discovery.Catalog), len(got))
	}
	for _, f := range got {
		if f.Status != discovery.StatusNotFound {
			t.Errorf("%s: esperava not_found, veio %s", f.Key, f.Status)
		}
	}
}

func TestDiscoverSystemdRunningAndStopped(t *testing.T) {
	h, d := newFakeHost(t)
	h.mkdir(filepath.Join(d.CgroupRoot, "system.slice", "cron.service"))
	h.write(filepath.Join(d.UnitDirs[0], "cron.service"), "")
	h.write(filepath.Join(d.UnitDirs[0], "nginx.service"), "") // instalado, sem cgroup
	h.mkdir(filepath.Join(d.CgroupRoot, "system.slice", "postgresql@16-main.service"))

	m := byKey(d.Discover())
	if f := m["cron"]; f.Status != discovery.StatusAvailable || f.Source != discovery.SourceSystemd || f.Unit != "cron.service" {
		t.Errorf("cron: %+v", f)
	}
	if f := m["nginx"]; f.Status != discovery.StatusStopped || f.Unit != "nginx.service" {
		t.Errorf("nginx: %+v", f)
	}
	if f := m["postgresql"]; f.Status != discovery.StatusAvailable || f.Unit != "postgresql@16-main.service" {
		t.Errorf("postgresql: %+v", f)
	}
}

func TestDiscoverSSHSocketActivation(t *testing.T) {
	h, d := newFakeHost(t)
	h.write(filepath.Join(d.UnitDirs[0], "ssh.socket"), "")
	h.write(filepath.Join(d.ProcRoot, "net", "tcp"),
		"  sl  local_address rem_address   st\n   0: 00000000:0016 00000000:0000 0A 00000000:00000000\n")
	if f := byKey(d.Discover())["ssh"]; f.Status != discovery.StatusAvailable || f.Unit != "ssh.socket" {
		t.Errorf("ssh: %+v", f)
	}
}

func TestDiscoverRedisInDockerByProcess(t *testing.T) {
	h, d := newFakeHost(t)
	h.proc(d, "100", "redis-server", "0::/system.slice/docker-abc123.scope", "")
	if f := byKey(d.Discover())["redis"]; f.Status != discovery.StatusAvailable || f.Source != discovery.SourceDocker {
		t.Errorf("redis: %+v", f)
	}
}

func TestDiscoverPostgresInDockerByProxy(t *testing.T) {
	h, d := newFakeHost(t)
	h.proc(d, "200", "docker-proxy", "0::/system.slice/docker.service",
		"/usr/bin/docker-proxy\x00-proto\x00tcp\x00-host-port\x0015432\x00-container-ip\x00172.17.0.2\x00-container-port\x005432\x00")
	if f := byKey(d.Discover())["postgresql"]; f.Status != discovery.StatusAvailable || f.Source != discovery.SourceDocker {
		t.Errorf("postgresql: %+v", f)
	}
}

func TestDiscoverRedisOnHostBeatsDocker(t *testing.T) {
	h, d := newFakeHost(t)
	h.proc(d, "100", "redis-server", "0::/user.slice/session-1.scope", "")
	h.proc(d, "101", "redis-server", "0::/system.slice/docker-abc.scope", "")
	if f := byKey(d.Discover())["redis"]; f.Source != discovery.SourceProcess {
		t.Errorf("redis: %+v", f)
	}
}

func TestDiscoverUFW(t *testing.T) {
	h, d := newFakeHost(t)
	h.write(filepath.Join(d.UnitDirs[0], "ufw.service"), "")
	h.write(d.UFWConf, "# comentário\nENABLED=no\n")
	if f := byKey(d.Discover())["ufw"]; f.Status != discovery.StatusStopped {
		t.Errorf("ufw desativado: %+v", f)
	}
	h.write(d.UFWConf, "ENABLED=yes\n")
	if f := byKey(d.Discover())["ufw"]; f.Status != discovery.StatusAvailable {
		t.Errorf("ufw ativo: %+v", f)
	}
}

func TestDiscoverIgnoresTemplateUnit(t *testing.T) {
	h, d := newFakeHost(t)
	h.write(filepath.Join(d.UnitDirs[0], "postgresql@.service"), "")
	if f := byKey(d.Discover())["postgresql"]; f.Status != discovery.StatusNotFound {
		t.Errorf("postgresql: %+v", f)
	}
}
