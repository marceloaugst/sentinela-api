package svcactions

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"sentinela/internal/discovery"
)

// TestPolkitRuleMatchesCatalog executa a regra polkit (deploy/50-sentinela-agent.rules) com um polkit simulado e
// confere que ela autoriza exatamente os verbos de "controllable" para cada unidade do catálogo, e nada além disso.
// A regra é a barreira do sistema operacional: se a API ou o agente forem comprometidos, é ela que impede, por exemplo,
// parar o SSH. Precisa do node; sem ele, o teste é pulado.
func TestPolkitRuleMatchesCatalog(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node não encontrado: regra polkit não verificada")
	}
	rule, err := os.ReadFile(filepath.Join("..", "..", "deploy", "50-sentinela-agent.rules"))
	if err != nil {
		t.Fatal(err)
	}

	type check struct {
		User, Action, Unit, Verb string
		Want                     bool
	}
	var checks []check
	add := func(user, unit, verb string, want bool) {
		checks = append(checks, check{user, "org.freedesktop.systemd1.manage-units", unit, verb, want})
	}
	verbs := []string{ActionStart, ActionStop, ActionRestart, "enable", "mask", "kill", "reload"}
	for _, spec := range discovery.Catalog {
		for _, u := range spec.Units {
			if base, ok := strings.CutSuffix(u, ".socket"); ok {
				u = base + ".service" // o comando vai para o .service (veja svcctl.TargetUnit)
			}
			if prefix, glob := strings.CutSuffix(u, "*"); glob {
				u = prefix + "x1.service"
			}
			for _, v := range verbs {
				add("sentinela-agent", u, v, Contains(controllable[spec.Key], v))
				add("outro-usuario", u, v, false)
			}
		}
	}
	add("sentinela-agent", "meuapp.service", ActionRestart, false)
	add("sentinela-agent", "ssh.service.evil", ActionRestart, false)
	add("sentinela-agent", "", ActionRestart, false)
	checks = append(checks, check{"sentinela-agent", "org.freedesktop.systemd1.reload-daemon", "nginx.service", ActionRestart, false})

	in, _ := json.Marshal(checks)
	script := `
var rules = [];
var polkit = { Result: { YES: "yes", NO: "no", NOT_HANDLED: null }, addRule: function (f) { rules.push(f); }, log: function () {} };
` + string(rule) + `
var checks = ` + string(in) + `;
var out = checks.map(function (c) {
  var action = { id: c.Action, lookup: function (k) { return k === "verb" ? c.Verb : k === "unit" ? c.Unit : undefined; } };
  return rules[0](action, { user: c.User }) === polkit.Result.YES;
});
console.log(JSON.stringify(out));
`
	cmd := exec.Command(node, "-e", script)
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node falhou: %v\n%s", err, b)
	}
	var got []bool
	if err := json.Unmarshal(b, &got); err != nil || len(got) != len(checks) {
		t.Fatalf("saída inesperada do node: %s", b)
	}
	for i, c := range checks {
		if got[i] != c.Want {
			t.Errorf("polkit: usuário=%s ação=%s unidade=%q verbo=%s → autorizado=%v; esperado %v",
				c.User, c.Action, c.Unit, c.Verb, got[i], c.Want)
		}
	}
}
