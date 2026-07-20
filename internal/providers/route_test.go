package providers

import "testing"

func TestParseMTRJSON(t *testing.T) {
	hops, err := parseMTRJSON([]byte(`{"report":{"hubs":[{"count":"1","host":"192.168.1.1","Loss%":0.0,"Avg":1.25},{"count":2,"host":"???","Loss%":100.0,"Avg":0.0}]}}`))
	if err != nil || len(hops) != 2 || hops[0].Address != "192.168.1.1" || hops[0].LatencyMS != 1.25 || hops[1].Address != "" {
		t.Fatalf("unexpected hops: %#v, %v", hops, err)
	}
}

func TestParseTraceroute(t *testing.T) {
	hops := parseTraceroute("1  192.168.1.1  1.234 ms\n2  *\n3  203.0.113.9  8.500 ms\n")
	if len(hops) != 3 || hops[0].Address != "192.168.1.1" || hops[1].Address != "" || hops[2].TTL != 3 {
		t.Fatalf("unexpected hops: %#v", hops)
	}
}
