package main

// Author: David Vanhoucke <dvanhoucke@redborder.com>

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const VERSION = "v1.5 (2026-06-13)"

type State struct {
	UUID       string `json:"uuid"`
	Status     string `json:"status"` // registered, claimed
	Token      string `json:"token,omitempty"`
	Hash       string `json:"hash"`
	Nodename   string `json:"nodename,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	ClientName string `json:"client_name,omitempty"`
}

type Config struct {
	ManagerURL   string `json:"manager_url"`
	APIAccessKey string `json:"api_access_key"`
	AlertURL     string `json:"alert_url"`
	Port         int    `json:"port"`
	Rate         int    `json:"rate"`
	Insecure     bool   `json:"insecure"`
	Domain       string `json:"domain"`
	Verbose      bool   `json:"verbose"`
	SensorType   int    `json:"type"`
}

func generateUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func loadState(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

func saveState(path string, state *State) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func getClient(insecure bool) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
	}
}

func register(cfg Config, state *State) error {
	client := getClient(cfg.Insecure)
	payload := map[string]interface{}{
		"order":  "register",
		"type":   cfg.SensorType,
		"hash":   state.Hash,
		"cpus":   2,
		"memory": 4194304,
	}
	data, _ := json.Marshal(payload)

	fmt.Printf("[*] Sending registration request to %s...\n", cfg.ManagerURL)
	resp, err := client.Post(cfg.ManagerURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("manager returned %d: %s", resp.StatusCode, string(body))
	}

	var res map[string]interface{}
	if err := json.Unmarshal(body, &res); err != nil {
		fmt.Printf("[-] Error parsing manager response: %v\n", err)
	}

	// DEBUG: Print all keys in the response
	fmt.Printf("[DEBUG] Response keys: ")
	for k := range res {
		fmt.Printf("%s ", k)
	}
	fmt.Println()

	if status, ok := res["status"].(string); ok && (status == "registered" || status == "claimed") {
		if uuid, ok := res["uuid"].(string); ok {
			state.UUID = uuid
		}
		if nodename, ok := res["nodename"].(string); ok {
			state.Nodename = nodename
		}
		if priv, ok := res["private_key"].(string); ok {
			state.PrivateKey = priv
		} else if cert, ok := res["cert"].(string); ok {
			var unquoted string
			if err := json.Unmarshal([]byte(cert), &unquoted); err == nil {
				state.PrivateKey = unquoted
			} else {
				state.PrivateKey = cert
			}
		}

		if client, ok := res["client_name"].(string); ok {
			state.ClientName = client
		} else if state.Nodename != "" {
			state.ClientName = state.Nodename
		}
		state.Status = status
		return nil
	}

	return fmt.Errorf("unexpected manager response status: %s", string(body))
}

func verify(cfg Config, state *State) error {
	client := getClient(cfg.Insecure)
	payload := map[string]interface{}{
		"order": "verify",
		"hash":  state.Hash,
		"uuid":  state.UUID,
	}
	data, _ := json.Marshal(payload)

	resp, err := client.Post(cfg.ManagerURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("[*] Manager response (verify): %s\n", string(body))
	var res map[string]interface{}
	json.Unmarshal(body, &res)

	// DEBUG: Print all keys in the response
	fmt.Printf("[DEBUG] Response keys (verify): ")
	for k := range res {
		fmt.Printf("%s ", k)
	}
	fmt.Println()

	if status, ok := res["status"].(string); ok {
		if nodename, ok := res["nodename"].(string); ok {
			state.Nodename = nodename
		}
		if priv, ok := res["private_key"].(string); ok {
			state.PrivateKey = priv
		} else if cert, ok := res["cert"].(string); ok {
			var unquoted string
			if err := json.Unmarshal([]byte(cert), &unquoted); err == nil {
				state.PrivateKey = unquoted
			} else {
				state.PrivateKey = cert
			}
		}

		if client, ok := res["client_name"].(string); ok {
			state.ClientName = client
		} else if state.Nodename != "" {
			state.ClientName = state.Nodename
		}
		state.Status = status
		return nil
	}

	return fmt.Errorf("verification failed: %s", string(body))
}

func signChefRequest(req *http.Request, clientName string, privateKeyPEM string) error {
	if privateKeyPEM == "" {
		return nil
	}

	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return fmt.Errorf("failed to decode private key PEM")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %v", err)
	}

	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	path := req.URL.Path
	if path == "" { path = "/" }

	hPath := sha1.New()
	hPath.Write([]byte(path))
	hashedPath := base64.StdEncoding.EncodeToString(hPath.Sum(nil))

	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewBuffer(body))
	}
	hBody := sha1.New()
	hBody.Write(body)
	hashedBody := base64.StdEncoding.EncodeToString(hBody.Sum(nil))

	canonicalReq := fmt.Sprintf("Method:%s\nHashed Path:%s\nX-Ops-Content-Hash:%s\nX-Ops-Timestamp:%s\nX-Ops-UserId:%s",
		req.Method, hashedPath, hashedBody, timestamp, clientName)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.Hash(0), []byte(canonicalReq))
	if err != nil {
		return fmt.Errorf("failed to sign: %v", err)
	}

	sigBase64 := base64.StdEncoding.EncodeToString(signature)

	req.Header.Set("X-Ops-Sign", "version=1.0")
	req.Header.Set("X-Ops-UserId", clientName)
	req.Header.Set("X-Ops-Timestamp", timestamp)
	req.Header.Set("X-Ops-Content-Hash", hashedBody)
	req.Header.Set("Accept", "application/json")

	for i := 0; i*60 < len(sigBase64); i++ {
		end := (i + 1) * 60
		if end > len(sigBase64) { end = len(sigBase64) }
		chunk := sigBase64[i*60:end]
		req.Header.Set(fmt.Sprintf("X-Ops-Authorization-%d", i+1), chunk)
	}

	return nil
}

func checkIn(cfg Config, state *State) error {
	client := getClient(cfg.Insecure)

	baseURL := strings.TrimSuffix(cfg.ManagerURL, "/")
	baseURL = strings.TrimSuffix(baseURL, "/register")

	if strings.HasSuffix(baseURL, "/sensors") {
		baseURL = strings.TrimSuffix(baseURL, "/sensors") + "/ips"
	}
	checkInURL := fmt.Sprintf("%s/has_new_config?sensor[uuid]=%s", baseURL, state.UUID)

	req, _ := http.NewRequest("GET", checkInURL, nil)

	clientName := state.ClientName
	if clientName == "" && cfg.APIAccessKey != "" {
		clientName = cfg.APIAccessKey
	}

	if state.PrivateKey != "" && clientName != "" {
		if err := signChefRequest(req, clientName, state.PrivateKey); err != nil {
			fmt.Printf("[-] Error signing request: %v\n", err)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return nil
	}

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		fmt.Printf("[!] NEW CONFIGURATION DETECTED! Ruleset UUID: %s\n", string(body))
		return nil
	}

	return fmt.Errorf("check-in failed with status %d: %s", resp.StatusCode, string(body))
}

func main() {
	configPath := flag.String("config", "", "JSON config file")
	managerURL := flag.String("manager", "", "Manager registration URL")
	apiKey := flag.String("api-key", "", "API Access Key")
	alertURL := flag.String("alert-url", "", "Alert URL")
	port := flag.Int("port", 3128, "Port (ignored)")
	rate := flag.Int("rate", 10, "Heartbeat rate")
	insecure := flag.Bool("insecure", true, "Skip TLS verification")
	domain := flag.String("domain", "redborder.cluster", "Redborder domain")
	verbose := flag.Bool("v", false, "Enable verbose logging")
	sensorType := flag.Int("type", 31, "Sensor type (31 for Client Proxy)")
	
	defaultState := "/sensor-data/proxy-state.json"
	if os.Getenv("SENSOR_NAME") != "" {
		defaultState = fmt.Sprintf("/sensor-data/proxy-state-%s.json", os.Getenv("SENSOR_NAME"))
	}
	stateFile := flag.String("state", defaultState, "Path to state file")
	flag.Parse()

	fmt.Printf("[+] Redborder Proxy Agent %s\n", VERSION)

	cfg := Config{
		ManagerURL:   *managerURL,
		APIAccessKey: *apiKey,
		AlertURL:     *alertURL,
		Port:         *port,
		Rate:         *rate,
		Insecure:     *insecure,
		Domain:       *domain,
		Verbose:      *verbose,
		SensorType:   *sensorType,
	}

	if *configPath != "" {
		f, err := os.ReadFile(*configPath)
		if err == nil {
			json.Unmarshal(f, &cfg)
		}
	}

	state, err := loadState(*stateFile)
	if err != nil {
		fmt.Println("[*] Initializing new sensor state...")
		state = &State{Hash: generateUUID(), Status: "unregistered"}
	}

	if cfg.ManagerURL != "" {
		for state.Status != "claimed" {
			if state.Status == "unregistered" {
				err = register(cfg, state)
				if err != nil {
					fmt.Printf("[-] Registration error: %v. Retrying in 10s...\n", err)
					time.Sleep(10 * time.Second)
					continue
				}
				fmt.Printf("[+] Registered! UUID: %s. Status: %s\n", state.UUID, state.Status)
				saveState(*stateFile, state)
			}

			if state.Status == "registered" {
				fmt.Printf("[*] Waiting for manager approval (claimed status) for UUID %s...\n", state.UUID)
				err = verify(cfg, state)
				if err != nil {
					fmt.Printf("[-] Verify error: %v. Retrying in 10s...\n", err)
					time.Sleep(10 * time.Second)
					continue
				}
				if state.Status != "claimed" {
					fmt.Println("[*] Status still 'registered'. Waiting 10s...")
					time.Sleep(10 * time.Second)
					continue
				}
				fmt.Println("[+] Sensor has been CLAIMED by manager.")
				saveState(*stateFile, state)
			}
		}
	}

	if cfg.AlertURL == "" && cfg.ManagerURL != "" {
		d := cfg.Domain
		if d == "" { d = "redborder.cluster" }
		cfg.AlertURL = fmt.Sprintf("https://http2k.%s/rbdata/%s/rb_event", d, state.UUID)

		u, err := url.Parse(cfg.ManagerURL)
		if err == nil {
			managerHost := u.Hostname()
			hostsEntry := fmt.Sprintf("%s http2k.%s\n", managerHost, d)
			f, err := os.OpenFile("/etc/hosts", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
			if err == nil {
				f.WriteString(hostsEntry)
				f.Close()
				fmt.Printf("[+] Updated /etc/hosts: %s", hostsEntry)
			}
		}
	}

	sensorName := state.Nodename
	if sensorName == "" { sensorName = os.Getenv("SENSOR_NAME") }
	fmt.Printf("[+] Proxy Agent active. UUID: %s. Nodename: %s\n", state.UUID, sensorName)

	// Initial heartbeat immediately after claiming
	if err := checkIn(cfg, state); err != nil && cfg.Verbose {
		fmt.Printf("[-] Initial heartbeat error: %v\n", err)
	}

	heartbeatTicker := time.NewTicker(time.Duration(cfg.Rate) * time.Minute)
	for {
		select {
		case <-heartbeatTicker.C:
			if err := checkIn(cfg, state); err != nil && cfg.Verbose {
				fmt.Printf("[-] Heartbeat error: %v\n", err)
			}
		}
	}
}
