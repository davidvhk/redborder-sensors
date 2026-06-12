package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// Proxy agent version
const Version = "1.0.0"

type AuthConfig struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

type Config struct {
	Port    int         `json:"port"`
	User    string      `json:"user"`
	Pass    string      `json:"pass"`
	Verbose bool        `json:"verbose"`
	Auth    *AuthConfig `json:"auth"`
}

var currentConfig = Config{
	Port:    8080,
	Verbose: false,
}

func main() {
	portFlag := flag.Int("port", 8080, "Port to listen on")
	configPath := flag.String("config", "", "Path to JSON configuration file")
	verbose := flag.Bool("v", false, "Enable verbose logging")
	flag.Parse()

	if *configPath != "" {
		data, err := os.ReadFile(*configPath)
		if err == nil {
			if err := json.Unmarshal(data, &currentConfig); err != nil {
				log.Fatalf("[-] Error parsing config: %v", err)
			}
			fmt.Printf("[+] Loaded configuration from %s\n", *configPath)
		} else {
			fmt.Printf("[-] Error loading config: %v\n", err)
		}
	}

	if *portFlag != 8080 {
		currentConfig.Port = *portFlag
	}
	if *verbose {
		currentConfig.Verbose = true
	}

	fmt.Printf("[+] Redborder Proxy Agent %s starting...\n", Version)
	if currentConfig.Auth != nil {
		fmt.Printf("[+] Authentication enabled (User: %s)\n", currentConfig.Auth.User)
	}

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", currentConfig.Port),
		Handler: http.HandlerFunc(handleProxy),
		// Disable HTTP/2 for the proxy to simplify CONNECT handling
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	fmt.Printf("[+] Listening on %s\n", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("[-] Proxy Server failed: %v", err)
	}
}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	if currentConfig.Verbose {
		fmt.Printf("[*] %s %s from %s\n", r.Method, r.URL.String(), r.RemoteAddr)
	}

	// Check Authentication
	if currentConfig.Auth != nil {
		auth := r.Header.Get("Proxy-Authorization")
		if auth == "" {
			w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy"`)
			http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
			return
		}

		payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusProxyAuthRequired)
			return
		}

		pair := strings.SplitN(string(payload), ":", 2)
		if len(pair) != 2 || pair[0] != currentConfig.Auth.User || pair[1] != currentConfig.Auth.Pass {
			if currentConfig.Verbose {
				fmt.Printf("[!] Unauthorized proxy access attempt for user: %s\n", pair[0])
			}
			http.Error(w, "Unauthorized", http.StatusProxyAuthRequired)
			return
		}
	}

	if r.Method == http.MethodConnect {
		handleConnect(w, r)
	} else {
		handleHTTP(w, r)
	}
}

func handleConnect(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		destConn.Close()
		return
	}
	
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		destConn.Close()
		return
	}

	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	// RequestURI must be empty for Client.Do
	r.RequestURI = ""
	
	// Remove Hop-by-hop headers
	removeHopByHopHeaders(r.Header)

	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	removeHopByHopHeaders(resp.Header)
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// Hop-by-hop headers. These are removed before forwarding the request.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te", // canonicalized version of "TE"
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopByHopHeaders(header http.Header) {
	for _, h := range hopHeaders {
		header.Del(h)
	}
}
