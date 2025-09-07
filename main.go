package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
)

type Config struct {
	verbose       bool
	showScore     bool
	minScore      int
	excludeStatic bool
	includeJS     bool
	dedupe        bool
}

var config Config

type urlCheck struct {
	name   string
	weight int
	check  func(*url.URL) bool
}

func init() {
	flag.BoolVar(&config.verbose, "v", false, "Verbose output (show why URLs are interesting)")
	flag.BoolVar(&config.showScore, "score", false, "Show interestingness score")
	flag.IntVar(&config.minScore, "min", 1, "Minimum interestingness score")
	flag.BoolVar(&config.excludeStatic, "no-static", true, "Exclude boring static files")
	flag.BoolVar(&config.includeJS, "js", false, "Include JavaScript files")
	flag.BoolVar(&config.dedupe, "dedupe", true, "Deduplicate by host+path+params")
}

func main() {
	flag.Parse()

	checks := []urlCheck{
		// Critical query string patterns (high weight)
		{
			name:   "sql-injection",
			weight: 3,
			check: func(u *url.URL) bool {
				for k, vv := range u.Query() {
					for _, v := range vv {
						kl := strings.ToLower(k)
						vl := strings.ToLower(v)
						if strings.Contains(vl, "select") || strings.Contains(vl, "union") ||
							strings.Contains(vl, "insert") || strings.Contains(vl, "update") ||
							strings.Contains(vl, "delete") || strings.Contains(vl, "drop") ||
							strings.Contains(kl, "id") || strings.Contains(kl, "user") {
							return true
						}
					}
				}
				return false
			},
		},

		// Interesting query string parameters
		{
			name:   "query-params",
			weight: 2,
			check: func(u *url.URL) bool {
				interesting := 0
				for k, vv := range u.Query() {
					for _, v := range vv {
						if isInterestingParam(k, v) {
							interesting++
						}
					}
				}
				return interesting > 0
			},
		},

		// Interesting extensions
		{
			name:   "extensions",
			weight: 2,
			check: func(u *url.URL) bool {
				interestingExts := []string{
					".php", ".phtml", ".asp", ".aspx", ".asmx", ".ashx",
					".cgi", ".pl", ".jsp", ".jspa", ".do", ".action",
					".json", ".xml", ".api", ".wadl", ".wsdl",
					".rb", ".py", ".sh", ".bat", ".ps1",
					".yaml", ".yml", ".toml", ".ini", ".conf", ".config",
					".bak", ".backup", ".old", ".save", ".swp", ".tmp",
					".git", ".svn", ".env", ".properties",
					".sql", ".db", ".sqlite",
				}

				p := strings.ToLower(u.EscapedPath())
				for _, ext := range interestingExts {
					if strings.HasSuffix(p, ext) {
						return true
					}
				}
				return false
			},
		},

		// Sensitive paths
		{
			name:   "sensitive-paths",
			weight: 3,
			check: func(u *url.URL) bool {
				p := strings.ToLower(u.EscapedPath())
				sensitivePaths := []string{
					"admin", "login", "auth", "api", "v1", "v2", "graphql",
					"swagger", "docs", "console", "phpmyadmin", "wp-admin",
					"jmx-console", "manager", "jenkins", "kibana", "grafana",
					".git", ".svn", ".env", "config", "backup", "dump",
					"temp", "tmp", "test", "dev", "stage", "debug",
					"private", "secret", "internal", "upload", "download",
					"include", "require", "proxy", "redirect", "forward",
					"exec", "execute", "eval", "system", "shell",
				}

				for _, sensitive := range sensitivePaths {
					if strings.Contains(p, sensitive) {
						return true
					}
				}
				return false
			},
		},

		// File operations
		{
			name:   "file-operations",
			weight: 3,
			check: func(u *url.URL) bool {
				for k, vv := range u.Query() {
					kl := strings.ToLower(k)
					if strings.Contains(kl, "file") || strings.Contains(kl, "path") ||
						strings.Contains(kl, "dir") || strings.Contains(kl, "folder") ||
						strings.Contains(kl, "read") || strings.Contains(kl, "write") ||
						strings.Contains(kl, "upload") || strings.Contains(kl, "download") {
						return true
					}
					for _, v := range vv {
						if strings.Contains(v, "../") || strings.Contains(v, "..\\") ||
							strings.Contains(v, "/etc/") || strings.Contains(v, "c:\\") {
							return true
						}
					}
				}
				return false
			},
		},

		// Non-standard ports
		{
			name:   "non-standard-port",
			weight: 1,
			check: func(u *url.URL) bool {
				port := u.Port()
				return port != "" && port != "80" && port != "443" && port != "8080" && port != "8443"
			},
		},

		// SSRF patterns
		{
			name:   "ssrf-patterns",
			weight: 3,
			check: func(u *url.URL) bool {
				for k, vv := range u.Query() {
					kl := strings.ToLower(k)
					if strings.Contains(kl, "url") || strings.Contains(kl, "uri") ||
						strings.Contains(kl, "redirect") || strings.Contains(kl, "return") ||
						strings.Contains(kl, "next") || strings.Contains(kl, "callback") ||
						strings.Contains(kl, "dest") || strings.Contains(kl, "target") {
						for _, v := range vv {
							if strings.HasPrefix(v, "http") || strings.HasPrefix(v, "//") ||
								strings.Contains(v, "localhost") || strings.Contains(v, "127.0.0.1") ||
								strings.Contains(v, "169.254") || strings.Contains(v, "0.0.0.0") {
								return true
							}
						}
					}
				}
				return false
			},
		},

		// Command injection patterns
		{
			name:   "command-injection",
			weight: 3,
			check: func(u *url.URL) bool {
				for _, vv := range u.Query() {
					for _, v := range vv {
						if strings.Contains(v, ";") || strings.Contains(v, "|") ||
							strings.Contains(v, "`") || strings.Contains(v, "$()") ||
							strings.Contains(v, "&&") || strings.Contains(v, "||") {
							return true
						}
					}
				}
				return false
			},
		},

		// Authentication/Session
		{
			name:   "auth-session",
			weight: 2,
			check: func(u *url.URL) bool {
				for k := range u.Query() {
					kl := strings.ToLower(k)
					if strings.Contains(kl, "token") || strings.Contains(kl, "session") ||
						strings.Contains(kl, "auth") || strings.Contains(kl, "key") ||
						strings.Contains(kl, "apikey") || strings.Contains(kl, "api_key") ||
						strings.Contains(kl, "password") || strings.Contains(kl, "passwd") ||
						strings.Contains(kl, "secret") || strings.Contains(kl, "jwt") {
						return true
					}
				}
				return false
			},
		},
	}

	seen := make(map[string]bool)
	var mu sync.Mutex

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		u, err := url.Parse(line)
		if err != nil {
			if config.verbose {
				fmt.Fprintf(os.Stderr, "Failed to parse URL %s: %v\n", line, err)
			}
			continue
		}

		// Skip boring static files unless explicitly included
		if config.excludeStatic && isBoringStaticFile(u) && !config.includeJS {
			continue
		}

		// Deduplication
		if config.dedupe {
			key := buildDedupeKey(u)
			mu.Lock()
			if seen[key] {
				mu.Unlock()
				continue
			}
			seen[key] = true
			mu.Unlock()
		}

		// Run checks and calculate score
		score := 0
		reasons := []string{}

		for _, check := range checks {
			if check.check(u) {
				score += check.weight
				reasons = append(reasons, check.name)
			}
		}

		// Output if meets minimum score
		if score >= config.minScore {
			output := line
			if config.showScore {
				output = fmt.Sprintf("[%d] %s", score, line)
			}
			if config.verbose && len(reasons) > 0 {
				output = fmt.Sprintf("%s (%s)", output, strings.Join(reasons, ", "))
			}
			fmt.Println(output)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
	}
}

func isInterestingParam(k, v string) bool {
	k = strings.ToLower(k)
	v = strings.ToLower(v)

	// Skip common tracking parameters
	if strings.HasPrefix(k, "utm_") || strings.HasPrefix(k, "ga_") ||
		k == "fbclid" || k == "gclid" || k == "ref" || k == "source" {
		return false
	}

	// Interesting value patterns
	interestingValues := strings.HasPrefix(v, "http") ||
		strings.Contains(v, "{") || strings.Contains(v, "[") ||
		strings.Contains(v, "/") || strings.Contains(v, "\\") ||
		strings.Contains(v, "<") || strings.Contains(v, ">") ||
		strings.Contains(v, "(") || strings.Contains(v, ")") ||
		strings.Contains(v, "eyj") || // JWT
		strings.Contains(v, "base64") ||
		strings.Contains(v, "..") ||
		strings.Contains(v, "%00") ||
		strings.Contains(v, "\x00")

	// Interesting key patterns
	interestingKeys := strings.Contains(k, "redirect") ||
		strings.Contains(k, "debug") ||
		strings.Contains(k, "test") ||
		strings.Contains(k, "file") ||
		strings.Contains(k, "path") ||
		strings.Contains(k, "template") ||
		strings.Contains(k, "include") ||
		strings.Contains(k, "require") ||
		strings.Contains(k, "url") ||
		strings.Contains(k, "uri") ||
		strings.Contains(k, "src") ||
		strings.Contains(k, "href") ||
		strings.Contains(k, "func") ||
		strings.Contains(k, "callback") ||
		strings.Contains(k, "exec") ||
		strings.Contains(k, "cmd") ||
		strings.Contains(k, "command") ||
		strings.Contains(k, "query") ||
		strings.Contains(k, "search") ||
		strings.Contains(k, "q")

	return interestingValues || interestingKeys
}

func isBoringStaticFile(u *url.URL) bool {
	boringExts := []string{
		".html", ".htm",
		".css", ".scss", ".sass", ".less",
		".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
		".eot", ".ttf", ".woff", ".woff2", ".otf",
		".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".webm",
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".zip", ".rar", ".tar", ".gz", ".7z",
	}

	// JavaScript is conditionally boring
	if !config.includeJS {
		boringExts = append(boringExts, ".js", ".map", ".min.js")
	}

	p := strings.ToLower(u.EscapedPath())
	for _, ext := range boringExts {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}

	return false
}

func buildDedupeKey(u *url.URL) string {
	// Get sorted parameter names for consistent deduplication
	params := make([]string, 0)
	for param := range u.Query() {
		params = append(params, param)
	}
	sort.Strings(params)

	// Build key from hostname, path, and sorted params
	key := fmt.Sprintf("%s%s?%s", u.Hostname(), u.EscapedPath(), strings.Join(params, "&"))
	return key
}