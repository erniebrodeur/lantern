package providers

import (
	"context"
	"encoding/json"
	"time"
)

type Descriptor struct {
	ID           string         `json:"id"`
	Capability   string         `json:"capability"`
	Label        string         `json:"label"`
	SupportedOS  []string       `json:"supportedOs"`
	OSPriorities map[string]int `json:"-"`
}

type Status struct {
	Capability string `json:"capability"`
	ProviderID string `json:"provider,omitempty"`
	Label      string `json:"label,omitempty"`
	OS         string `json:"os"`
	Status     string `json:"status"`
	Available  bool   `json:"available"`
	Path       string `json:"path,omitempty"`
	Version    string `json:"version,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type Request struct {
	RunID     string            `json:"runId"`
	Target    string            `json:"target"`
	Arguments []string          `json:"arguments,omitempty"`
	Options   map[string]string `json:"options,omitempty"`
}

type EntityRef struct {
	Type string `json:"type"`
	Key  string `json:"key"`
}

type Evidence struct {
	ID             int64           `json:"id,omitempty"`
	ProviderRunID  string          `json:"providerRunId,omitempty"`
	ProviderID     string          `json:"provider,omitempty"`
	Capability     string          `json:"capability,omitempty"`
	Kind           string          `json:"kind"`
	Subject        EntityRef       `json:"subject"`
	Object         *EntityRef      `json:"object,omitempty"`
	PayloadVersion int             `json:"payloadVersion"`
	Payload        json.RawMessage `json:"payload"`
	ObservedAt     time.Time       `json:"observedAt"`
	Confidence     float64         `json:"confidence"`
}

type Progress struct {
	Phase     string `json:"phase,omitempty"`
	Task      string `json:"task,omitempty"`
	Percent   string `json:"percent,omitempty"`
	Remaining string `json:"remaining,omitempty"`
	Completed int    `json:"completed,omitempty"`
	Total     int    `json:"total,omitempty"`
}

type Event struct {
	Type     string    `json:"type"`
	Progress *Progress `json:"progress,omitempty"`
	Evidence *Evidence `json:"evidence,omitempty"`
	Message  string    `json:"message,omitempty"`
	Stream   string    `json:"stream,omitempty"`
	ExitCode *int      `json:"exitCode,omitempty"`
}

type Selection struct {
	Provider Provider
	Status   Status
}

type EmitFunc func(Event) error

type Provider interface {
	Describe() Descriptor
	Probe(context.Context) Status
	Run(context.Context, Request, EmitFunc) error
}

type Run struct {
	ID         string     `json:"id"`
	ScanID     string     `json:"scanId"`
	Capability string     `json:"capability"`
	ProviderID string     `json:"provider"`
	Label      string     `json:"label,omitempty"`
	Status     string     `json:"status"`
	StartedAt  time.Time  `json:"startedAt"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
	Error      string     `json:"error,omitempty"`
}

type EvidenceQuery struct {
	Kind        string
	SubjectType string
	SubjectKey  string
	Limit       int
}

type ObservedHost struct {
	Hostname string `json:"hostname,omitempty"`
	Reason   string `json:"reason,omitempty"`
}
