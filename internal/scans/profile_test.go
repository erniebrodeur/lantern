package scans

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseArgumentText(t *testing.T) {
	t.Parallel()
	arguments, err := ParseArgumentText(`-sT --script-args 'http.useragent=Lantern Dev' -p "80,443"`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"-sT", "--script-args", "http.useragent=Lantern Dev", "-p", "80,443"}
	if !reflect.DeepEqual(arguments, want) {
		t.Fatalf("arguments = %#v, want %#v", arguments, want)
	}
}

func TestParseArgumentTextRejectsLanternOwnedArguments(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"-oX scan.xml", "-oAresults", "--stats-every 5s", "--resume old.xml"} {
		if _, err := ParseArgumentText(value); err == nil || !strings.Contains(err.Error(), "Lantern owns") {
			t.Fatalf("ParseArgumentText(%q) returned %v", value, err)
		}
	}
}

func TestBuiltInProfilesAreCloned(t *testing.T) {
	t.Parallel()
	profiles := BuiltInProfiles()
	profiles[0].Arguments[0] = "changed"
	fresh := BuiltInProfiles()
	if fresh[0].Arguments[0] == "changed" {
		t.Fatal("built-in profile arguments were mutated")
	}
}

func TestBuiltInProfilesLimitRetries(t *testing.T) {
	t.Parallel()
	for _, profile := range BuiltInProfiles() {
		if !strings.Contains(profile.ArgumentText, "--max-retries 2") {
			t.Fatalf("profile %q does not limit retries: %q", profile.ID, profile.ArgumentText)
		}
	}
}

func TestArgumentsRequestOSDetection(t *testing.T) {
	t.Parallel()
	if !argumentsRequestOSDetection([]string{"-sT", "-O"}) || !argumentsRequestOSDetection([]string{"-A"}) {
		t.Fatal("OS detection flags were not recognized")
	}
	if argumentsRequestOSDetection([]string{"-sT", "-sV"}) {
		t.Fatal("ordinary scan arguments requested OS detection")
	}
}

func TestResolveArgumentsAddsOSDetection(t *testing.T) {
	t.Parallel()
	arguments, requested := resolveArguments([]string{"-sT"}, "192.168.1.1", true)
	if !requested || strings.Join(arguments, " ") != "-sT -Pn -O --stats-every 1s -oX - 192.168.1.1" {
		t.Fatalf("unexpected resolved arguments: %#v, %t", arguments, requested)
	}
	arguments, requested = resolveArguments([]string{"-A"}, "printer.local", false)
	if !requested || strings.Count(strings.Join(arguments, " "), "-A") != 1 {
		t.Fatalf("custom OS detection was not preserved: %#v, %t", arguments, requested)
	}
}

func TestResolveArgumentsSkipsDiscoveryForSingleIPPortScans(t *testing.T) {
	t.Parallel()
	for _, target := range []string{"192.168.1.42", "192.168.1.42/32", "2001:db8::42", "2001:db8::42/128"} {
		arguments, _ := resolveArguments([]string{"-sT"}, target, false)
		if !containsArgument(arguments, "-Pn") {
			t.Fatalf("single-IP target %q did not receive -Pn: %#v", target, arguments)
		}
	}
	for _, test := range []struct {
		target    string
		arguments []string
	}{
		{target: "192.168.1.0/24", arguments: []string{"-sT"}},
		{target: "192.168.1.42/32", arguments: []string{"-sn"}},
	} {
		arguments, _ := resolveArguments(test.arguments, test.target, false)
		if containsArgument(arguments, "-Pn") {
			t.Fatalf("target %q with arguments %#v unexpectedly received -Pn", test.target, test.arguments)
		}
	}
}

func TestParseArgumentTextErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "empty", value: "  ", want: "required"},
		{name: "too long", value: strings.Repeat("x", 8193), want: "too long"},
		{name: "null", value: "-sT\x00", want: "null byte"},
		{name: "unfinished escape", value: `-sT \`, want: "unfinished escape"},
		{name: "unclosed single quote", value: `-p '80`, want: "unclosed quote"},
		{name: "unclosed double quote", value: `-p "80`, want: "unclosed quote"},
		{name: "too many", value: strings.Repeat("x ", 257), want: "too many"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseArgumentText(test.value)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ParseArgumentText() error = %v, want %q", err, test.want)
			}
		})
	}
	arguments, err := ParseArgumentText(`-sT "" '' escaped\ value`)
	if err != nil || !reflect.DeepEqual(arguments, []string{"-sT", "", "", "escaped value"}) {
		t.Fatalf("empty/escaped arguments = %#v, %v", arguments, err)
	}
}

func TestValidateArgumentsErrors(t *testing.T) {
	t.Parallel()
	tooMany := make([]string, 257)
	if err := ValidateArguments(tooMany); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("too many error = %v", err)
	}
	if err := ValidateArguments([]string{"-sT", "bad\x00value"}); err == nil || !strings.Contains(err.Error(), "null byte") {
		t.Fatalf("null error = %v", err)
	}
	for _, argument := range []string{"-oX", "-oNresult", "-oG", "-oSresult", "-oA", "--resume", "--append-output", "--stats-every", "--stats-every=2s"} {
		if err := ValidateArguments([]string{argument}); err == nil || !strings.Contains(err.Error(), "Lantern owns") {
			t.Fatalf("ValidateArguments(%q) = %v", argument, err)
		}
	}
}
