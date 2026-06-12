package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

// AuthConfig defines Basic Auth credentials
type AuthConfig struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

// EndpointConfig defines the behavior of a specific URL path
type EndpointConfig struct {
	Path            string            `json:"path"`
	Methods         []string          `json:"methods"`
	Status          int               `json:"status"`
	Body            string            `json:"body"`
	Headers         map[string]string `json:"headers"`          // Headers to set in response
	ExpectedHeaders map[string]string `json:"expected_headers"` // Headers required in request
	Auth            *AuthConfig       `json:"auth"`
}

// SSLConfig defines SSL/TLS settings
type SSLConfig struct {
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

// Config is the top-level configuration structure
type Config struct {
	Port      int              `json:"port"`
	Verbose   bool             `json:"verbose"`
	SSL       SSLConfig        `json:"ssl"`
	Endpoints []EndpointConfig `json:"endpoints"`
}

var globalVerbose bool

func main() {
	configPath := flag.String("config", "config.json", "Path to the JSON configuration file")
	verbose := flag.Bool("v", false, "Enable verbose logging")
	flag.Parse()

	config, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("[-] Failed to load config: %v", err)
	}

	if *verbose {
		config.Verbose = true
	}
	globalVerbose = config.Verbose

	for _, ep := range config.Endpoints {
		epCopy := ep // Capture loop variable
		http.HandleFunc(epCopy.Path, func(w http.ResponseWriter, r *http.Request) {
			handleEndpoint(w, r, epCopy)
		})
		fmt.Printf("[+] Registered endpoint: %s\n", epCopy.Path)
	}

	addr := fmt.Sprintf(":%d", config.Port)
	if config.SSL.Enabled {
		fmt.Printf("[+] Starting HTTPS server on port %d...\n", config.Port)
		if err := http.ListenAndServeTLS(addr, config.SSL.CertFile, config.SSL.KeyFile, nil); err != nil {
			log.Fatalf("[-] HTTPS Server failed: %v", err)
		}
	} else {
		fmt.Printf("[+] Starting HTTP server on port %d...\n", config.Port)
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Fatalf("[-] HTTP Server failed: %v", err)
		}
	}
}

func loadConfig(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	if config.Port == 0 {
		config.Port = 8080
	}

	return &config, nil
}

func handleEndpoint(w http.ResponseWriter, r *http.Request, ep EndpointConfig) {
	if globalVerbose {
		fmt.Printf("[*] %s %s from %s\n", r.Method, r.URL.Path, r.RemoteAddr)
		for k, v := range r.Header {
			fmt.Printf("    > %s: %s\n", k, v)
		}
	}

	// Check Method
	if len(ep.Methods) > 0 {
		allowed := false
		for _, m := range ep.Methods {
			if strings.EqualFold(m, r.Method) {
				allowed = true
				break
			}
		}
		if !allowed {
			if globalVerbose {
				fmt.Printf("[!] Method %s not allowed for %s\n", r.Method, r.URL.Path)
			}
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	// Check Auth
	if ep.Auth != nil {
		user, pass, ok := r.BasicAuth()
		if !ok || user != ep.Auth.User || pass != ep.Auth.Pass {
			if globalVerbose {
				fmt.Printf("[!] Auth failed for %s\n", r.URL.Path)
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// Check Expected Headers
	for k, expectedVal := range ep.ExpectedHeaders {
		gotVal := r.Header.Get(k)
		if gotVal == "" {
			if globalVerbose {
				fmt.Printf("[!] Missing expected header: %s\n", k)
			}
			http.Error(w, fmt.Sprintf("Missing Header: %s", k), http.StatusBadRequest)
			return
		}
		if expectedVal != "" && gotVal != expectedVal {
			if globalVerbose {
				fmt.Printf("[!] Header mismatch for %s: expected '%s', got '%s'\n", k, expectedVal, gotVal)
			}
			http.Error(w, fmt.Sprintf("Invalid Header Value: %s", k), http.StatusBadRequest)
			return
		}
	}

	// Set custom headers
	for k, v := range ep.Headers {
		w.Header().Set(k, v)
	}

	// Set status and body
	status := ep.Status
	if status == 0 {
		status = http.StatusOK
	}

	w.WriteHeader(status)
	fmt.Fprint(w, ep.Body)
}
