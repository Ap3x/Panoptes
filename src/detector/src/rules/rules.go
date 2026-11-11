// Package rules loads detection rules from YAML and compiles each step's condition with expr.
//
// A rule is a sequence of one or more steps. Each step is an expr boolean expression evaluated
// against one event (the same JSON object the service writes to pano.log). Steps must match in
// order, on events that share a join key, within maxspan of the first step. A one-step rule is
// a plain single-event rule.
package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"gopkg.in/yaml.v3"
)

type Severity string
type Action string

const (
	ActionAlert      Action = "alert"
	ActionKill       Action = "kill"
	ActionQuarantine Action = "quarantine"
)

// File is the on-disk shape of a rule. Fields mirror EQL's `sequence by X with maxspan=Y`.
type File struct {
	Name        string        `yaml:"name"`
	Description string        `yaml:"description"`
	Severity    Severity      `yaml:"severity"`
	Action      Action        `yaml:"action"`
	By          string        `yaml:"by"`      // default join field for every step
	MaxSpan     time.Duration `yaml:"maxspan"` // 0 = no limit (one-step rules)
	Until       *StepFile     `yaml:"until"`   // optional: drop partial matches for a key when this matches
	Target      string        `yaml:"target"`  // field of the last event naming the process to act on; default "PID"
	Sequence    []StepFile    `yaml:"sequence"`
}

// StepFile accepts either a bare string or {where: ..., by: ...} for a per-step join field
// (e.g. step 1 joins on PID, step 2 on TargetProcessId).
type StepFile struct {
	Where string `yaml:"where"`
	By    string `yaml:"by"`
}

func (s *StepFile) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		s.Where = n.Value
		return nil
	}
	type plain StepFile
	return n.Decode((*plain)(s))
}

type Step struct {
	Source  string
	By      string
	Program *vm.Program
}

type Rule struct {
	File
	Steps []Step
	Until *Step
}

// Options shared by every compiled expression. There is no Env, so identifiers resolve
// dynamically against the event map and a field the event lacks evaluates to nil.
func compileOptions() []expr.Option {
	return []expr.Option{
		expr.AllowUndefinedVariables(),
		expr.AsBool(),
		// expr has no bitwise operators and the hook logs hex fields as strings ("0x40")
		expr.Function("hasFlag", func(p ...any) (any, error) {
			v, err := toUint(p[0])
			if err != nil {
				return false, nil
			}
			m, err := toUint(p[1])
			if err != nil {
				return nil, err
			}
			return v&m == m, nil
		}, new(func(any, any) bool)),
		expr.Function("lower", func(p ...any) (any, error) {
			s, _ := p[0].(string)
			return strings.ToLower(s), nil
		}, new(func(any) string)),
	}
}

func toUint(v any) (uint64, error) {
	switch x := v.(type) {
	case float64:
		return uint64(x), nil
	case int:
		return uint64(x), nil
	case string:
		return strconv.ParseUint(strings.TrimPrefix(strings.ToLower(x), "0x"), 16, 64)
	}
	return 0, fmt.Errorf("not a number: %v", v)
}

func Compile(f File) (*Rule, error) {
	if f.Name == "" {
		return nil, fmt.Errorf("rule has no name")
	}
	if len(f.Sequence) == 0 {
		return nil, fmt.Errorf("%s: empty sequence", f.Name)
	}
	if len(f.Sequence) > 1 && f.MaxSpan == 0 {
		return nil, fmt.Errorf("%s: multi-step rules need a maxspan", f.Name)
	}
	if f.Action == "" {
		f.Action = ActionAlert
	}
	if f.Target == "" {
		f.Target = "PID"
	}
	r := &Rule{File: f}
	for i, s := range f.Sequence {
		by := s.By
		if by == "" {
			by = f.By
		}
		if by == "" && len(f.Sequence) > 1 {
			return nil, fmt.Errorf("%s: step %d has no join field (set `by`)", f.Name, i+1)
		}
		p, err := expr.Compile(s.Where, compileOptions()...)
		if err != nil {
			return nil, fmt.Errorf("%s: step %d: %w", f.Name, i+1, err)
		}
		r.Steps = append(r.Steps, Step{Source: s.Where, By: by, Program: p})
	}
	if f.Until != nil {
		by := f.Until.By
		if by == "" {
			by = f.By
		}
		p, err := expr.Compile(f.Until.Where, compileOptions()...)
		if err != nil {
			return nil, fmt.Errorf("%s: until: %w", f.Name, err)
		}
		r.Until = &Step{Source: f.Until.Where, By: by, Program: p}
	}
	return r, nil
}

// LoadDir compiles every *.yaml / *.yml file in dir. A file may hold several rules as a YAML list.
func LoadDir(dir string) ([]*Rule, error) {
	var out []*Rule
	// Detections are reported by name, so two rules with one name would be indistinguishable
	seen := make(map[string]string)
	for _, pattern := range []string{"*.yaml", "*.yml"} {
		paths, _ := filepath.Glob(filepath.Join(dir, pattern))
		for _, path := range paths {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			var files []File
			if err := yaml.Unmarshal(data, &files); err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			for _, f := range files {
				r, err := Compile(f)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", path, err)
				}
				if other, dup := seen[r.Name]; dup {
					return nil, fmt.Errorf("%s: rule %q is also defined in %s", path, r.Name, other)
				}
				seen[r.Name] = path
				out = append(out, r)
			}
		}
	}
	return out, nil
}

func (s Step) Match(event map[string]any) bool {
	ok, err := expr.Run(s.Program, event)
	return err == nil && ok == true
}
