// Command frontier is the single entry point for the frontier-learning loop:
//
//	go run ./cmd/frontier
//
// It vets, builds both binaries, runs every test with the race detector and
// prints the pass rate (s/n) per level. A change stays only when its level's
// rate rises and no lower level drops (see CHANGELOG.md).
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// level maps a package suffix to the frontier level it measures.
var levels = []struct{ name, pkg string }{
	{"L0 format: JCS", "/internal/jcs"},
	{"L0 format: records", "/internal/record"},
	{"L0 format: tree", "/internal/merkle"},
	{"L0 format: checkpoints", "/internal/checkpoint"},
	{"L1 transport: proxy", "/internal/proxy"},
	{"L1-L5 engine: frames, runs, atomicity", "/internal/engine"},
	{"L2-L3 e2e: identity and scope (real Bao)", "/internal/e2e"},
	{"L5 export: .tkb (strict zip)", "/internal/bundle"},
}

type event struct {
	Action  string
	Package string
	Test    string
}

func run(name string, args ...string) error {
	c := exec.Command(name, args...)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	return c.Run()
}

func main() {
	for _, step := range [][]string{
		{"go", "vet", "./..."},
		{"go", "build", "-o", os.DevNull, "./cmd/service-openbao-tracekit"},
		{"go", "build", "-o", os.DevNull, "./cmd/tkbao-proxy"},
	} {
		if err := run(step[0], step[1:]...); err != nil {
			fmt.Fprintln(os.Stderr, "frontier: step failed:", strings.Join(step, " "))
			os.Exit(1)
		}
	}
	cmd := exec.Command("go", "test", "-race", "-count=1", "-json", "./...")
	out, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	pass, total := map[string]int{}, map[string]int{}
	failed := map[string][]string{}
	skipped := map[string][]string{}
	seen := map[string]bool{}
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var ev event
		if json.Unmarshal(sc.Bytes(), &ev) != nil || ev.Test == "" {
			continue
		}
		seen[ev.Package] = true
		switch ev.Action {
		case "pass":
			pass[ev.Package]++
			total[ev.Package]++
		case "skip":
			skipped[ev.Package] = append(skipped[ev.Package], ev.Test)
		case "fail":
			total[ev.Package]++
			failed[ev.Package] = append(failed[ev.Package], ev.Test)
		}
	}
	waitErr := cmd.Wait()
	bad := waitErr != nil
	if waitErr != nil {
		fmt.Fprintln(os.Stderr, "frontier: go test failed:", waitErr)
	}
	for _, l := range levels {
		pkgName := ""
		for pkg := range seen {
			if strings.HasSuffix(pkg, l.pkg) {
				pkgName = pkg
			}
		}
		if pkgName == "" {
			fmt.Printf("%-40s   0/0   NOT MEASURED: no tests ran\n", l.name)
			bad = true
			continue
		}
		n := total[pkgName]
		if n == 0 {
			fmt.Printf("%-40s   0/0   NOT MEASURED: all %d skipped\n", l.name, len(skipped[pkgName]))
		} else {
			fmt.Printf("%-40s %3d/%-3d %.3f\n", l.name, pass[pkgName], n, float64(pass[pkgName])/float64(n))
		}
		if len(skipped[pkgName]) > 0 {
			sort.Strings(skipped[pkgName])
			fmt.Printf("    NOT MEASURED: %d skipped (missing bao, python3 or TRACEKIT_PYTHON):\n", len(skipped[pkgName]))
			for _, t := range skipped[pkgName] {
				fmt.Printf("      skip %s\n", t)
			}
			bad = true
		}
		sort.Strings(failed[pkgName])
		for _, t := range failed[pkgName] {
			fmt.Printf("    FAIL %s\n", t)
			bad = true
		}
	}
	if bad {
		os.Exit(1)
	}
}
