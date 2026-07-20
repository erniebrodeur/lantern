package scans_test

import (
	"strings"
	"testing"

	"github.com/erniebrodeur/lantern/internal/scans"
)

const sampleNmapXML = `<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.98" xmloutputversion="1.05">
  <host><status state="up" reason="conn-refused"/>
    <address addr="192.168.1.42" addrtype="ipv4"/>
    <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Brother Industries"/>
    <hostnames><hostname name="printer.local" type="PTR"/></hostnames>
    <ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="Brother Web UI" version="1.0" method="probed" conf="10"/></port></ports>
  </host>
  <runstats><finished time="1784310000" elapsed="1.2" summary="done" exit="success"/><hosts up="1" down="1" total="2"/></runstats>
</nmaprun>`

func TestParseNmapXML(t *testing.T) {
	result, err := scans.ParseNmapXML(strings.NewReader(sampleNmapXML))
	if err != nil {
		t.Fatal(err)
	}
	if result.NmapVersion != "7.98" || result.HostsUp != 1 || result.HostsTotal != 2 {
		t.Fatalf("unexpected summary: %#v", result)
	}
	if len(result.Hosts) != 1 || result.Hosts[0].Addresses[1].Vendor != "Brother Industries" {
		t.Fatalf("unexpected host: %#v", result.Hosts)
	}
	port := result.Hosts[0].Ports[0]
	if port.Number != 80 || port.Service != "http" || port.Product != "Brother Web UI" || port.Confidence != 10 {
		t.Fatalf("unexpected port: %#v", port)
	}
}

func TestParseNmapXMLRejectsIncompleteScan(t *testing.T) {
	_, err := scans.ParseNmapXML(strings.NewReader(`<nmaprun scanner="nmap"><host>`))
	if err == nil {
		t.Fatal("expected malformed XML to fail")
	}
}

func TestParseNmapXMLRejectsNestedNmapDocument(t *testing.T) {
	_, err := scans.ParseNmapXML(strings.NewReader(`<wrapper><nmaprun scanner="nmap"><runstats><finished exit="success"/><hosts/></runstats></nmaprun></wrapper>`))
	if err == nil {
		t.Fatal("expected a non-Nmap document root to fail")
	}
}

func TestParseNmapXMLReportsProgressWithoutRetainingXML(t *testing.T) {
	input := strings.Replace(sampleNmapXML, "<host>", `<taskprogress task="Service scan" percent="42.50" remaining="12"/><host>`, 1)
	var progress scans.Progress
	_, err := scans.ParseNmapXMLWithProgress(strings.NewReader(input), func(current scans.Progress) {
		progress = current
	})
	if err != nil {
		t.Fatal(err)
	}
	if progress.Task != "Service scan" || progress.Percent != "42.50" || progress.Remaining != "12" {
		t.Fatalf("unexpected progress: %#v", progress)
	}
}

func TestParseNmapXMLPublishesHostHintThenFinalObservation(t *testing.T) {
	input := strings.Replace(sampleNmapXML, "<host>", `<hosthint><status state="up" reason="unknown-response"/><address addr="192.168.1.42" addrtype="ipv4"/></hosthint><host>`, 1)
	var observations []scans.HostObservation
	result, err := scans.ParseNmapXMLIncremental(strings.NewReader(input), nil, func(host scans.HostObservation) error {
		observations = append(observations, host)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Hosts) != 1 || len(observations) != 2 {
		t.Fatalf("unexpected observations: result=%#v callbacks=%#v", result.Hosts, observations)
	}
	if !observations[0].Provisional || observations[1].Provisional {
		t.Fatalf("unexpected provisional lifecycle: %#v", observations)
	}
	if len(observations[1].Ports) != 1 || observations[1].Ports[0].Number != 80 {
		t.Fatalf("final observation lost service evidence: %#v", observations[1])
	}
}

func TestParseNmapXMLOSMatches(t *testing.T) {
	input := strings.Replace(sampleNmapXML, "  </host>", `    <os><osmatch name="Apple macOS 13 - 14" accuracy="96"><osclass type="general purpose" vendor="Apple" osfamily="macOS" osgen="14.X" accuracy="96"><cpe>cpe:/o:apple:mac_os_x:14</cpe></osclass></osmatch></os>
  </host>`, 1)
	result, err := scans.ParseNmapXML(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	host := result.Hosts[0]
	if host.OSStatus != "matched" || len(host.OSMatches) != 1 {
		t.Fatalf("unexpected OS evidence: %#v", host)
	}
	match := host.OSMatches[0]
	if match.Name != "Apple macOS 13 - 14" || match.Accuracy != 96 || len(match.Classes) != 1 || match.Classes[0].Vendor != "Apple" || len(match.Classes[0].CPEs) != 1 {
		t.Fatalf("unexpected OS match: %#v", match)
	}
}
