package scans

import (
	"encoding/xml"
	"fmt"
	"io"
)

type Progress struct {
	Task      string `json:"task"`
	Percent   string `json:"percent"`
	Remaining string `json:"remaining"`
}

type nmapRunStats struct {
	Finished struct {
		Exit string `xml:"exit,attr"`
	} `xml:"finished"`
	Hosts struct {
		Up    int `xml:"up,attr"`
		Down  int `xml:"down,attr"`
		Total int `xml:"total,attr"`
	} `xml:"hosts"`
}

type nmapHost struct {
	Status struct {
		State  string `xml:"state,attr"`
		Reason string `xml:"reason,attr"`
	} `xml:"status"`
	Addresses []struct {
		Address string `xml:"addr,attr"`
		Type    string `xml:"addrtype,attr"`
		Vendor  string `xml:"vendor,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
		Type string `xml:"type,attr"`
	} `xml:"hostnames>hostname"`
	Ports []struct {
		Protocol string `xml:"protocol,attr"`
		Number   int    `xml:"portid,attr"`
		State    struct {
			Name   string `xml:"state,attr"`
			Reason string `xml:"reason,attr"`
		} `xml:"state"`
		Service struct {
			Name       string `xml:"name,attr"`
			Product    string `xml:"product,attr"`
			Version    string `xml:"version,attr"`
			ExtraInfo  string `xml:"extrainfo,attr"`
			Method     string `xml:"method,attr"`
			Confidence int    `xml:"conf,attr"`
			Tunnel     string `xml:"tunnel,attr"`
		} `xml:"service"`
	} `xml:"ports>port"`
	OSMatches []struct {
		Name     string `xml:"name,attr"`
		Accuracy int    `xml:"accuracy,attr"`
		Classes  []struct {
			Type       string   `xml:"type,attr"`
			Vendor     string   `xml:"vendor,attr"`
			Family     string   `xml:"osfamily,attr"`
			Generation string   `xml:"osgen,attr"`
			Accuracy   int      `xml:"accuracy,attr"`
			CPEs       []string `xml:"cpe"`
		} `xml:"osclass"`
	} `xml:"os>osmatch"`
}

func ParseNmapXML(reader io.Reader) (Result, error) {
	return ParseNmapXMLWithProgress(reader, nil)
}

func ParseNmapXMLWithProgress(reader io.Reader, onProgress func(Progress)) (Result, error) {
	return ParseNmapXMLIncremental(reader, onProgress, nil)
}

func ParseNmapXMLIncremental(reader io.Reader, onProgress func(Progress), onHost func(HostObservation) error) (Result, error) {
	decoder := xml.NewDecoder(reader)
	decoder.Strict = true
	result := Result{Hosts: make([]HostObservation, 0)}
	var runStats nmapRunStats
	seenRoot := false
	closedRoot := false
	seenRunStats := false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Result{}, fmt.Errorf("parse Nmap XML: %w", err)
		}
		switch element := token.(type) {
		case xml.StartElement:
			if !seenRoot && element.Name.Local != "nmaprun" {
				return Result{}, fmt.Errorf("unexpected Nmap XML document root %q", element.Name.Local)
			}
			switch element.Name.Local {
			case "nmaprun":
				if seenRoot {
					return Result{}, fmt.Errorf("unexpected nested Nmap XML document")
				}
				seenRoot = true
				scanner := attribute(element.Attr, "scanner")
				if scanner != "nmap" {
					return Result{}, fmt.Errorf("unexpected Nmap XML document")
				}
				result.NmapVersion = attribute(element.Attr, "version")
				result.XMLOutputVersion = attribute(element.Attr, "xmloutputversion")
			case "host":
				var host nmapHost
				if err := decoder.DecodeElement(&host, &element); err != nil {
					return Result{}, fmt.Errorf("parse Nmap host: %w", err)
				}
				observation, err := normalizeHost(host, false)
				if err != nil {
					return Result{}, err
				}
				result.Hosts = append(result.Hosts, observation)
				if onHost != nil {
					if err := onHost(observation); err != nil {
						return Result{}, fmt.Errorf("save Nmap host: %w", err)
					}
				}
			case "hosthint":
				var host nmapHost
				if err := decoder.DecodeElement(&host, &element); err != nil {
					return Result{}, fmt.Errorf("parse Nmap host hint: %w", err)
				}
				observation, err := normalizeHost(host, true)
				if err != nil {
					return Result{}, err
				}
				if onHost != nil {
					if err := onHost(observation); err != nil {
						return Result{}, fmt.Errorf("save Nmap host hint: %w", err)
					}
				}
			case "taskprogress":
				if onProgress != nil {
					onProgress(Progress{
						Task:      attribute(element.Attr, "task"),
						Percent:   attribute(element.Attr, "percent"),
						Remaining: attribute(element.Attr, "remaining"),
					})
				}
			case "runstats":
				if err := decoder.DecodeElement(&runStats, &element); err != nil {
					return Result{}, fmt.Errorf("parse Nmap run statistics: %w", err)
				}
				seenRunStats = true
			}
		case xml.EndElement:
			if element.Name.Local == "nmaprun" {
				closedRoot = true
			}
		}
	}
	if !seenRoot || !closedRoot || !seenRunStats {
		return Result{}, fmt.Errorf("incomplete Nmap XML document")
	}
	if runStats.Finished.Exit != "success" {
		return Result{}, fmt.Errorf("Nmap XML did not report a successful scan")
	}
	result.HostsUp = runStats.Hosts.Up
	result.HostsDown = runStats.Hosts.Down
	result.HostsTotal = runStats.Hosts.Total
	return result, nil
}

func normalizeHost(source nmapHost, provisional bool) (HostObservation, error) {
	host := HostObservation{
		State:       source.Status.State,
		StateReason: source.Status.Reason,
		Provisional: provisional,
		Addresses:   make([]Address, 0, len(source.Addresses)),
		Hostnames:   make([]Hostname, 0, len(source.Hostnames)),
		Ports:       make([]Port, 0, len(source.Ports)),
		OSMatches:   make([]OSMatch, 0, len(source.OSMatches)),
	}
	for _, address := range source.Addresses {
		host.Addresses = append(host.Addresses, Address{
			Address: address.Address,
			Type:    address.Type,
			Vendor:  address.Vendor,
		})
	}
	for _, hostname := range source.Hostnames {
		host.Hostnames = append(host.Hostnames, Hostname{Name: hostname.Name, Type: hostname.Type})
	}
	for _, port := range source.Ports {
		if port.Number < 1 || port.Number > 65535 {
			return HostObservation{}, fmt.Errorf("invalid port number %d", port.Number)
		}
		host.Ports = append(host.Ports, Port{
			Protocol:    port.Protocol,
			Number:      port.Number,
			State:       port.State.Name,
			StateReason: port.State.Reason,
			Service:     port.Service.Name,
			Product:     port.Service.Product,
			Version:     port.Service.Version,
			ExtraInfo:   port.Service.ExtraInfo,
			Method:      port.Service.Method,
			Confidence:  port.Service.Confidence,
			Tunnel:      port.Service.Tunnel,
		})
	}
	for _, sourceMatch := range source.OSMatches {
		match := OSMatch{Name: sourceMatch.Name, Accuracy: sourceMatch.Accuracy, Classes: make([]OSClass, 0, len(sourceMatch.Classes))}
		for _, sourceClass := range sourceMatch.Classes {
			match.Classes = append(match.Classes, OSClass{
				Type:       sourceClass.Type,
				Vendor:     sourceClass.Vendor,
				Family:     sourceClass.Family,
				Generation: sourceClass.Generation,
				Accuracy:   sourceClass.Accuracy,
				CPEs:       append([]string(nil), sourceClass.CPEs...),
			})
		}
		host.OSMatches = append(host.OSMatches, match)
	}
	if len(host.OSMatches) > 0 {
		host.OSStatus = "matched"
	}
	return host, nil
}

func attribute(attributes []xml.Attr, name string) string {
	for _, item := range attributes {
		if item.Name.Local == name {
			return item.Value
		}
	}
	return ""
}
