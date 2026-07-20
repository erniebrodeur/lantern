package scans

import (
	"fmt"
	"strings"
	"unicode"
)

// DefaultProfileID identifies the built-in profile used when none is supplied.
const DefaultProfileID = "builtin:quick"

var builtInProfiles = []Profile{
	{ID: "builtin:discovery", Label: "Discovery", ArgumentText: "-sn --max-retries 2 --reason", Arguments: []string{"-sn", "--max-retries", "2", "--reason"}, BuiltIn: true},
	{ID: DefaultProfileID, Label: "Quick", ArgumentText: "-sT -sV --version-light --top-ports 100 --max-retries 2 --reason", Arguments: []string{"-sT", "-sV", "--version-light", "--top-ports", "100", "--max-retries", "2", "--reason"}, BuiltIn: true},
	{ID: "builtin:standard", Label: "Standard", ArgumentText: "-sT -sV --top-ports 1000 --max-retries 2 --reason", Arguments: []string{"-sT", "-sV", "--top-ports", "1000", "--max-retries", "2", "--reason"}, BuiltIn: true},
	{ID: "builtin:deep", Label: "Deep", ArgumentText: "-sT -sV --version-all -p- --max-retries 2 --reason", Arguments: []string{"-sT", "-sV", "--version-all", "-p-", "--max-retries", "2", "--reason"}, BuiltIn: true},
}

// BuiltInProfiles returns defensive copies of all built-in scan profiles.
func BuiltInProfiles() []Profile {
	profiles := make([]Profile, len(builtInProfiles))
	for index, profile := range builtInProfiles {
		profiles[index] = cloneProfile(profile)
	}
	return profiles
}

// BuiltInProfile returns a defensive copy of the named built-in profile.
func BuiltInProfile(identifier string) (Profile, bool) {
	for _, profile := range builtInProfiles {
		if profile.ID == identifier {
			return cloneProfile(profile), true
		}
	}
	return Profile{}, false
}

// ParseArgumentText tokenizes shell-like argument text without invoking a shell.
// It also rejects output and progress flags that Lantern manages itself.
func ParseArgumentText(value string) ([]string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("scan arguments are required")
	}
	if len(value) > 8192 {
		return nil, fmt.Errorf("scan arguments are too long")
	}
	if strings.ContainsRune(value, 0) {
		return nil, fmt.Errorf("scan arguments contain a null byte")
	}
	var arguments []string
	var current strings.Builder
	var quote rune
	escaped := false
	started := false
	flush := func() {
		if started {
			arguments = append(arguments, current.String())
			current.Reset()
			started = false
		}
	}
	for _, character := range value {
		if escaped {
			current.WriteRune(character)
			escaped = false
			started = true
			continue
		}
		if character == '\\' && quote != '\'' {
			escaped = true
			started = true
			continue
		}
		if quote != 0 {
			if character == quote {
				quote = 0
			} else {
				current.WriteRune(character)
			}
			started = true
			continue
		}
		if character == '\'' || character == '"' {
			quote = character
			started = true
			continue
		}
		if unicode.IsSpace(character) {
			flush()
			continue
		}
		current.WriteRune(character)
		started = true
	}
	if escaped {
		return nil, fmt.Errorf("scan arguments end with an unfinished escape")
	}
	if quote != 0 {
		return nil, fmt.Errorf("scan arguments contain an unclosed quote")
	}
	flush()
	if len(arguments) > 256 {
		return nil, fmt.Errorf("scan arguments contain too many values")
	}
	if err := validateProfileArguments(arguments); err != nil {
		return nil, err
	}
	return arguments, nil
}

func validateProfileArguments(arguments []string) error {
	for _, argument := range arguments {
		lower := strings.ToLower(argument)
		if lower == "-ox" || strings.HasPrefix(lower, "-ox") || lower == "-on" || strings.HasPrefix(lower, "-on") ||
			lower == "-og" || strings.HasPrefix(lower, "-og") || lower == "-os" || strings.HasPrefix(lower, "-os") ||
			lower == "-oa" || strings.HasPrefix(lower, "-oa") || lower == "--resume" || lower == "--append-output" ||
			lower == "--stats-every" || strings.HasPrefix(lower, "--stats-every=") {
			return fmt.Errorf("Lantern owns Nmap output and progress arguments; remove %q", argument)
		}
	}
	return nil
}

// ValidateArguments applies the same restrictions used for stored custom
// profiles to an already-tokenized argument list.
func ValidateArguments(arguments []string) error {
	if len(arguments) > 256 {
		return fmt.Errorf("scan arguments contain too many values")
	}
	for _, argument := range arguments {
		if strings.ContainsRune(argument, 0) {
			return fmt.Errorf("scan arguments contain a null byte")
		}
	}
	return validateProfileArguments(arguments)
}

func cloneProfile(profile Profile) Profile {
	profile.Arguments = append([]string(nil), profile.Arguments...)
	return profile
}
