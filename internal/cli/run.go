package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jedi-knights/wireaudit/internal/analyzer"
	"github.com/jedi-knights/wireaudit/internal/probe"
	"github.com/jedi-knights/wireaudit/internal/report"
)

// Exit codes, per the CLI contract: 0 means no Must Fix finding, 1 means at
// least one Must Fix finding, 2 means the run itself could not complete.
const (
	ExitOK          = 0
	ExitMustFix     = 1
	ExitUsageOrTool = 2
)

// Run parses args, executes one analyzer run, renders the report to stdout,
// and returns the process exit code. It never calls os.Exit itself, so it
// remains testable as a plain function call.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	cfg, err := ParseFlags(args)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return ExitUsageOrTool
	}

	endpoints, err := resolveEndpoints(cfg)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return ExitUsageOrTool
	}

	headers, err := parseHeaders(cfg.Headers)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return ExitUsageOrTool
	}

	analyzerCfg := analyzer.Config{
		Endpoints:          endpoints,
		Headers:            headers,
		Categories:         toSet(splitNonEmpty(cfg.Categories, ",")),
		ExcludeRules:       toSet(cfg.ExcludeRules),
		Timeout:            cfg.Timeout,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		AllowUnsafeWrites:  cfg.AllowUnsafeWrites,
		Concurrency:        cfg.Concurrency,
	}

	rpt, err := analyzer.Run(ctx, analyzerCfg)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return ExitUsageOrTool
	}

	if renderErr := renderReport(stdout, cfg.Format, rpt); renderErr != nil {
		_, _ = fmt.Fprintln(stderr, renderErr)
		return ExitUsageOrTool
	}

	if rpt.HasMustFix() {
		return ExitMustFix
	}
	return ExitOK
}

func renderReport(w io.Writer, format string, rpt *report.Report) error {
	if format == "json" {
		return report.RenderJSON(w, rpt)
	}
	return report.RenderHuman(w, rpt)
}

// resolveEndpoints builds the endpoint list from --endpoint, --endpoints-file,
// or the "GET /" default, each resolved against cfg.Target.
func resolveEndpoints(cfg Config) ([]probe.Endpoint, error) {
	specs := cfg.Endpoints
	if cfg.EndpointsFile != "" {
		fromFile, err := readEndpointsFile(cfg.EndpointsFile)
		if err != nil {
			return nil, err
		}
		specs = fromFile
	}
	if len(specs) == 0 {
		specs = []string{"GET /"}
	}

	endpoints := make([]probe.Endpoint, 0, len(specs))
	for _, spec := range specs {
		ep, err := parseEndpointSpec(cfg.Target, spec)
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, ep)
	}
	return endpoints, nil
}

func parseEndpointSpec(target, spec string) (probe.Endpoint, error) {
	method, path, ok := strings.Cut(strings.TrimSpace(spec), " ")
	if !ok {
		return probe.Endpoint{}, fmt.Errorf("cli: endpoint %q must be \"METHOD path\"", spec)
	}
	return probe.Endpoint{
		Method: strings.ToUpper(strings.TrimSpace(method)),
		URL:    strings.TrimRight(target, "/") + path,
	}, nil
}

// readEndpointsFile reads one "METHOD path" endpoint spec per line, skipping
// blank lines and lines starting with "#".
func readEndpointsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cli: opening endpoints file: %w", err)
	}
	defer func() { _ = f.Close() }()

	var specs []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		specs = append(specs, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("cli: reading endpoints file: %w", err)
	}
	return specs, nil
}

// parseHeaders parses each "Name: value" spec into the map Session.Do
// expects, merging repeated names into one slice of values.
func parseHeaders(specs []string) (map[string][]string, error) {
	headers := make(map[string][]string, len(specs))
	for _, spec := range specs {
		name, value, ok := strings.Cut(spec, ":")
		if !ok {
			return nil, fmt.Errorf("cli: header %q must be \"Name: value\"", spec)
		}
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		headers[name] = append(headers[name], value)
	}
	return headers, nil
}

func splitNonEmpty(s, sep string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, sep)
}

func toSet(values []string) map[string]bool {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]bool, len(values))
	for _, v := range values {
		set[v] = true
	}
	return set
}
