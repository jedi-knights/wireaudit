package cli

import (
	"flag"
	"fmt"
	"strings"
	"time"
)

// Config is the fully parsed CLI configuration for one run.
type Config struct {
	Target             string
	Endpoints          []string // each "METHOD path", relative to Target
	EndpointsFile      string
	Headers            []string // each "Name: value"
	Categories         string   // comma-separated; empty means all
	ExcludeRules       []string
	Format             string // "human" or "json"
	Timeout            time.Duration
	InsecureSkipVerify bool
	AllowUnsafeWrites  bool
	Concurrency        int
}

// repeatedFlag implements flag.Value for a flag that may be passed more than
// once, accumulating every occurrence.
type repeatedFlag struct {
	values *[]string
}

func (r repeatedFlag) String() string {
	if r.values == nil {
		return ""
	}
	return strings.Join(*r.values, ",")
}

func (r repeatedFlag) Set(v string) error {
	*r.values = append(*r.values, v)
	return nil
}

// ParseFlags parses args (excluding the program name) into a Config.
func ParseFlags(args []string) (Config, error) {
	fs := flag.NewFlagSet("wireaudit", flag.ContinueOnError)

	var cfg Config
	fs.StringVar(&cfg.Target, "target", "", "base URL of the API to probe (required)")
	fs.Var(repeatedFlag{&cfg.Endpoints}, "endpoint", `endpoint to probe, e.g. "GET /v1/users/42" (repeatable; default: probe "/")`)
	fs.StringVar(&cfg.EndpointsFile, "endpoints-file", "", "file with one \"METHOD path\" endpoint per line (mutually exclusive with --endpoint)")
	fs.Var(repeatedFlag{&cfg.Headers}, "header", `header to send on every request, e.g. "Authorization: Bearer token" (repeatable)`)
	fs.StringVar(&cfg.Categories, "categories", "", "comma-separated category allowlist (default: all)")
	fs.Var(repeatedFlag{&cfg.ExcludeRules}, "exclude-rule", "check ID to skip, e.g. CACHE-003 (repeatable)")
	fs.StringVar(&cfg.Format, "format", "human", `output format: "human" or "json"`)
	fs.DurationVar(&cfg.Timeout, "timeout", 10*time.Second, "per-request timeout")
	fs.BoolVar(&cfg.InsecureSkipVerify, "insecure-skip-verify", false, "disable TLS certificate verification (never use against production targets)")
	fs.BoolVar(&cfg.AllowUnsafeWrites, "allow-unsafe-writes", false, "permit CACHE-005 to send a real PUT/PATCH/DELETE against the target")
	fs.IntVar(&cfg.Concurrency, "concurrency", 4, "maximum endpoints probed in parallel")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	if c.Target == "" {
		return fmt.Errorf("cli: --target is required")
	}
	if len(c.Endpoints) > 0 && c.EndpointsFile != "" {
		return fmt.Errorf("cli: --endpoint and --endpoints-file are mutually exclusive")
	}
	if c.Format != "human" && c.Format != "json" {
		return fmt.Errorf("cli: --format must be \"human\" or \"json\", got %q", c.Format)
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("cli: --timeout must be positive, got %s", c.Timeout)
	}
	return nil
}
