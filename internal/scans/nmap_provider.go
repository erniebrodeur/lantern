package scans

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/erniebrodeur/lantern/internal/providers"
)

type nmapProvider struct {
	configuredPath string
	mu             sync.RWMutex
	path           string
}

type nmapSummary struct {
	NmapVersion      string `json:"nmapVersion,omitempty"`
	XMLOutputVersion string `json:"xmlOutputVersion,omitempty"`
	HostsUp          int    `json:"hostsUp"`
	HostsDown        int    `json:"hostsDown"`
	HostsTotal       int    `json:"hostsTotal"`
	Observations     int    `json:"observations"`
	Partial          bool   `json:"partial,omitempty"`
}

func newNmapProvider(configuredPath string) providers.Provider {
	return &nmapProvider{configuredPath: configuredPath}
}

func (p *nmapProvider) Describe() providers.Descriptor {
	return providers.Descriptor{
		ID: "nmap", Capability: "scan", Label: "Nmap",
		SupportedOS: []string{"darwin", "linux"}, OSPriorities: map[string]int{"darwin": 100, "linux": 100},
	}
}

func (p *nmapProvider) Probe(parent context.Context) providers.Status {
	status := providers.Status{Capability: "scan", ProviderID: "nmap", Label: "Nmap", Status: "unavailable"}
	path := providers.ResolveExecutable(p.configuredPath, "nmap", nil)
	if path == "" {
		status.Reason = fmt.Sprintf("%s was not found", p.configuredPath)
		return status
	}
	p.mu.Lock()
	p.path = path
	p.mu.Unlock()
	status.Available = true
	status.Status = "available"
	status.Path = path
	return status
}

func (p *nmapProvider) Run(parent context.Context, request providers.Request, emit providers.EmitFunc) error {
	p.mu.RLock()
	path := p.path
	p.mu.RUnlock()
	if path == "" {
		return errors.New("Nmap provider has not passed its availability probe")
	}
	if len(request.Arguments) == 0 {
		return errors.New("Nmap provider requires scan arguments")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	command := providers.CommandContext(ctx, path, request.Arguments...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		return err
	}
	if err := command.Start(); err != nil {
		return err
	}
	var readers sync.WaitGroup
	readers.Add(1)
	go func() {
		defer readers.Done()
		scanner := bufio.NewScanner(stderr)
		scanner.Buffer(make([]byte, 64*1024), maxOutputLineBytes)
		for scanner.Scan() {
			if emitErr := emit(providers.Event{Type: "log", Stream: "stderr", Message: scanner.Text() + "\n"}); emitErr != nil {
				cancel()
				return
			}
		}
	}()
	result, parseErr := ParseNmapXMLIncremental(stdout, func(progress Progress) {
		_ = emit(providers.Event{Type: "progress", Progress: &providers.Progress{
			Phase: "scan", Task: progress.Task, Percent: progress.Percent, Remaining: progress.Remaining,
		}})
	}, func(host HostObservation) error {
		payload, err := json.Marshal(host)
		if err != nil {
			return err
		}
		subject := providers.EntityRef{Type: "scan-target", Key: request.Target}
		if address, ok := hostIPAddress(host); ok {
			subject = providers.EntityRef{Type: "address", Key: address.Address}
		}
		return emit(providers.Event{Type: "evidence", Evidence: &providers.Evidence{
			Kind: "host.observation", Subject: subject, PayloadVersion: 1,
			Payload: payload, ObservedAt: time.Now().UTC(), Confidence: 1,
		}})
	})
	if parseErr != nil {
		cancel()
		_, _ = io.Copy(io.Discard, stdout)
	}
	readers.Wait()
	waitErr := command.Wait()
	exitCode := 0
	if command.ProcessState != nil {
		exitCode = command.ProcessState.ExitCode()
	}
	if err := emit(providers.Event{Type: "complete", ExitCode: &exitCode}); err != nil && parseErr == nil {
		parseErr = err
	}
	summary := nmapSummary{
		NmapVersion: result.NmapVersion, XMLOutputVersion: result.XMLOutputVersion,
		HostsUp: result.HostsUp, HostsDown: result.HostsDown, HostsTotal: result.HostsTotal,
		Observations: len(result.Hosts), Partial: waitErr != nil || parseErr != nil,
	}
	if summary.HostsTotal == 0 && len(result.Hosts) > 0 {
		for _, host := range result.Hosts {
			summary.HostsTotal++
			if host.State == "up" {
				summary.HostsUp++
			} else if host.State == "down" {
				summary.HostsDown++
			}
		}
	}
	payload, summaryErr := json.Marshal(summary)
	if summaryErr == nil {
		summaryErr = emit(providers.Event{Type: "evidence", Evidence: &providers.Evidence{
			Kind: "scan.summary", Subject: providers.EntityRef{Type: "scan-target", Key: request.Target},
			PayloadVersion: 1, Payload: payload, ObservedAt: time.Now().UTC(), Confidence: 1,
		}})
	}
	if summaryErr != nil && parseErr == nil {
		parseErr = summaryErr
	}
	if parent.Err() != nil {
		return parent.Err()
	}
	if waitErr != nil {
		return waitErr
	}
	if parseErr != nil {
		return parseErr
	}
	return nil
}
