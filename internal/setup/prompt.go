package setup

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// maskToken returns a masked version of the token, keeping the first 4 and
// last 4 characters to make visual verification easier.
func maskToken(t string) string {
	if t == "" {
		return ""
	}
	if len(t) <= 8 {
		return strings.Repeat("*", len(t))
	}
	return t[:4] + strings.Repeat("*", 8) + t[len(t)-4:]
}

// promptToken reads a token from stdin without echo. Requires a TTY.
func promptToken() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("no TTY available to read the token; set GITLAB_TOKEN or use --gitlab-token")
	}
	fmt.Fprint(os.Stderr, "GitLab Personal Access Token (scope api): ")
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// promptYesNo asks the user for confirmation. Without a TTY it returns defaultYes.
func promptYesNo(question string, defaultYes bool) (bool, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return defaultYes, nil
	}
	suffix := "[y/N]"
	if defaultYes {
		suffix = "[Y/n]"
	}
	fmt.Fprintf(os.Stderr, "%s %s ", question, suffix)
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil {
		return false, err
	}
	line = strings.ToLower(strings.TrimSpace(line))
	if line == "" {
		return defaultYes, nil
	}
	return line == "y" || line == "yes", nil
}
