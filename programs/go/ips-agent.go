package main

// Author: David Vanhoucke <dvanhoucke@redborder.com>

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const VERSION = "v1.4 (2026-05-30)"

type SnortAlert struct {
	Timestamp      int64  `json:"timestamp"`
	SensorIDSnort  int    `json:"sensor_id_snort"`
	Action         string `json:"action"`
	SigGenerator   int    `json:"sig_generator"`
	SigID          int    `json:"sig_id"`
	Rev            int    `json:"rev"`
	Priority       string `json:"priority"`
	Classification string `json:"classification"`
	Msg            string `json:"msg"`
	Payload        string `json:"payload"`
	L4ProtoName    string `json:"l4_proto_name"`
	L4Proto        int    `json:"l4_proto"`
	EthSrc         string `json:"ethsrc"`
	EthDst         string `json:"ethdst"`
	EthSrcVendor   string `json:"ethsrc_vendor"`
	EthDstVendor   string `json:"ethdst_vendor"`
	EthType        int    `json:"ethtype"`
	Vlan           int    `json:"vlan"`
	VlanName       string `json:"vlan_name"`
	VlanPriority   int    `json:"vlan_priority"`
	VlanDrop       int    `json:"vlan_drop"`
	EthLength      int    `json:"ethlength"`
	EthLengthRange string `json:"ethlength_range"`
	SrcPort        int    `json:"src_port"`
	SrcPortName    string `json:"src_port_name"`
	DstPort        int    `json:"dst_port"`
	DstPortName    string `json:"dst_port_name"`
	SrcAsNum       int    `json:"src_asnum"`
	Src            string `json:"src"`
	SrcName        string `json:"src_name"`
	DstAsNum       string `json:"dst_asnum"`
	DstName        string `json:"dst_name"`
	Dst            string `json:"dst"`
	TTL            int    `json:"ttl"`
	TOS            int    `json:"tos"`
	ID             int    `json:"id"`
	IPLen          int    `json:"iplen"`
	IPLenRange     string `json:"iplen_range"`
	DgmLen         int    `json:"dgmlen"`
	TcpSeq         uint32 `json:"tcpseq"`
	TcpAck         uint32 `json:"tcpack"`
	TcpLen         int    `json:"tcplen"`
	TcpWindow      int    `json:"tcpwindow"`
	TcpFlags       string `json:"tcpflags"`
	SensorType     string `json:"sensor_type"`
	SensorIP       string `json:"sensor_ip"`
	SensorUUID     string `json:"sensor_uuid"`
	SensorName     string `json:"sensor_name"`
}

type IPSScenario struct {
	Name     string   `json:"name"`
	Messages []string `json:"messages"`
	SigID    int      `json:"sig_id"`
	Weight   int      `json:"weight"`
	Priority int      `json:"priority"`
	SrcCIDR  string   `json:"src_cidr"`
	DstCIDR  string   `json:"dst_cidr"`
	Protos   []string `json:"protos"`
	Ports    []int    `json:"ports"`
}

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
	ManagerURL    string        `json:"manager_url"`
	APIAccessKey  string        `json:"api_access_key"`
	AlertURL      string        `json:"alert_url"`
	Target        string        `json:"target"`
	Port          int           `json:"port"`
	Rate          int           `json:"rate"`
	Scenarios     []IPSScenario `json:"scenarios"`
	Insecure      bool          `json:"insecure"`
	Domain        string        `json:"domain"`
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
		"type":   32, // IPS type
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
	fmt.Printf("[*] Manager response: %s\n", string(body))
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
			// Some versions return the key in "cert" field and it might be double-quoted/escaped
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
			// Some versions return the key in "cert" field and it might be double-quoted/escaped
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

	// Chef Protocol v1.0 Legacy (matching working discovery)
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

	// Canonical Request for v1.0 (5 lines, plain UserId)
	canonicalReq := fmt.Sprintf("Method:%s\nHashed Path:%s\nX-Ops-Content-Hash:%s\nX-Ops-Timestamp:%s\nX-Ops-UserId:%s",
		req.Method, hashedPath, hashedBody, timestamp, clientName)

	fmt.Printf("[DEBUG] Signing with v1.0 Legacy Protocol:\n---\n%s\n---\n", canonicalReq)

	// Legacy 1.0 requires RSA_private_encrypt of the string itself (with PKCS1 padding)
	// In Go, this is achieved by SignPKCS1v15 with Hash = 0 (Raw)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.Hash(0), []byte(canonicalReq))
	if err != nil {
		return fmt.Errorf("failed to sign: %v", err)
	}

	sigBase64 := base64.StdEncoding.EncodeToString(signature)

	// Add headers
	req.Header.Set("X-Ops-Sign", "version=1.0")
	req.Header.Set("X-Ops-UserId", clientName)
	req.Header.Set("X-Ops-Timestamp", timestamp)
	req.Header.Set("X-Ops-Content-Hash", hashedBody)
	req.Header.Set("Accept", "application/json")

	// Split signature into 60-char chunks
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

	// Construct the polling URL from ManagerURL
	// manager_url: https://manager/api/v1/sensors
	// target route: https://manager/api/v1/ips/has_new_config
	baseURL := strings.TrimSuffix(cfg.ManagerURL, "/")
	baseURL = strings.TrimSuffix(baseURL, "/register")

	// Replace 'sensors' with 'ips' if present, as seen in manager route list
	if strings.HasSuffix(baseURL, "/sensors") {
		baseURL = strings.TrimSuffix(baseURL, "/sensors") + "/ips"
	}

	checkInURL := fmt.Sprintf("%s/has_new_config?sensor[uuid]=%s", baseURL, state.UUID)

	fmt.Printf("[*] Checking for new configuration at %s...\n", checkInURL)
	req, _ := http.NewRequest("GET", checkInURL, nil)

	clientName := state.ClientName
	if clientName == "" && cfg.APIAccessKey != "" {
		clientName = cfg.APIAccessKey
	}

	if state.PrivateKey != "" && clientName != "" {
		fmt.Printf("[DEBUG] Signing request with clientName: %s\n", clientName)
		if err := signChefRequest(req, clientName, state.PrivateKey); err != nil {
			fmt.Printf("[-] Error signing request: %v\n", err)
		}
	} else {
		fmt.Printf("[DEBUG] Skipping signing: PrivateKey empty=%v, ClientName empty=%v\n", state.PrivateKey == "", clientName == "")
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[-] HTTP error during check-in: %v\n", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		fmt.Println("[+] No new configuration (304 Not Modified). Manager timestamp updated.")
		return nil
	}

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		fmt.Printf("[!] NEW CONFIGURATION DETECTED! Ruleset UUID: %s\n", string(body))
		return nil
	}

	fmt.Printf("[-] Check-in failed with status %d: %s\n", resp.StatusCode, string(body))
	return fmt.Errorf("check-in failed with status %d: %s", resp.StatusCode, string(body))
}

func getRandomIP(cidr string) string {
	if cidr == "" {
		return fmt.Sprintf("%d.%d.%d.%d", nrand(254)+1, nrand(256), nrand(256), nrand(256))
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "127.0.0.1"
	}
	ip := make(net.IP, len(ipnet.IP))
	copy(ip, ipnet.IP)
	for i := range ipnet.Mask {
		if ipnet.Mask[i] != 255 {
			ip[i] = (ip[i] & ipnet.Mask[i]) | (byte(nrand(256)) & ^ipnet.Mask[i])
		}
	}
	return ip.String()
}

func nrand(n int) int {
	res, _ := rand.Int(rand.Reader, big.NewInt(int64(n)))
	return int(res.Int64())
}

func pickScenario(scenarios []IPSScenario) *IPSScenario {
	if len(scenarios) == 0 {
		return &IPSScenario{Name: "Generic Attack", SigID: 1000001, Weight: 100}
	}
	total := 0
	for _, s := range scenarios {
		total += s.Weight
	}
	r := nrand(total)
	for _, s := range scenarios {
		r -= s.Weight
		if r < 0 {
			return &s
		}
	}
	return &scenarios[0]
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "127.0.0.1"
}

func main() {
	configPath := flag.String("config", "", "JSON config file")
	managerURL := flag.String("manager", "", "Manager registration URL (e.g. https://manager/api/v1/sensors)")
	alertURL := flag.String("alert-url", "", "HTTPS URL to send alerts (http2k service)")
	apiKey := flag.String("api-key", "", "API Access Key to use as username")
	target := flag.String("target", "127.0.0.1", "Syslog fallback target IP")
	port := flag.Int("port", 514, "Syslog fallback target port")
	rate := flag.Int("rate", 1, "Alerts per minute")

	defaultState := "/sensor-data/ips-state.json"
	if os.Getenv("SENSOR_NAME") != "" {
		defaultState = fmt.Sprintf("/sensor-data/ips-state-%s.json", os.Getenv("SENSOR_NAME"))
	}
	stateFile := flag.String("state", defaultState, "Path to state file")

	insecure := flag.Bool("insecure", true, "Skip TLS verification for manager/alerts")
	flag.Parse()

	fmt.Printf("[+] Redborder IPS Agent %s\n", VERSION)

	cfg := Config{
		ManagerURL:   *managerURL,
		APIAccessKey: *apiKey,
		AlertURL:     *alertURL,
		Target:       *target,
		Port:         *port,
		Rate:         *rate,
		Insecure:     *insecure,
		Scenarios: []IPSScenario{
			{
				Name:     "SQL Injection",
				Messages: []string{"INDICATOR-SQL injection attempt", "SQL-Injection - Found 'OR 1=1'"},
				SigID:    1000001,
				Weight:   40,
				Priority: 1,
				SrcCIDR:  "192.168.1.0/24",
				Protos:   []string{"TCP"},
				Ports:    []int{80, 443},
			},
		},
	}

	if *configPath != "" {
		f, err := os.ReadFile(*configPath)
		if err == nil {
			if err := json.Unmarshal(f, &cfg); err != nil {
				fmt.Printf("[-] Error parsing config: %v\n", err)
			}
		}
	}

	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "manager":
			cfg.ManagerURL = *managerURL
		case "api-key":
			cfg.APIAccessKey = *apiKey
		case "alert-url":
			cfg.AlertURL = *alertURL
		case "target":
			cfg.Target = *target
		case "port":
			cfg.Port = *port
		case "rate":
			cfg.Rate = *rate
		}
	})

	var state *State
	var err error
	state, err = loadState(*stateFile)
	if err != nil {
		fmt.Println("[*] Initializing new sensor state...")
		state = &State{Hash: generateUUID(), Status: "unregistered"}
	}
	if state.Status == "" {
		if state.UUID != "" {
			state.Status = "claimed"
		} else {
			state.Status = "unregistered"
		}
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
	} else if state.UUID == "" {
		state.UUID = "standalone-" + generateUUID()
		state.Status = "claimed"
		fmt.Printf("[*] Standalone mode. Generated UUID: %s\n", state.UUID)
		saveState(*stateFile, state)
	}

	// Auto-construct AlertURL if not provided and managerURL is available
	if cfg.AlertURL == "" && cfg.ManagerURL != "" {
		domain := cfg.Domain
		if domain == "" {
			domain = "redborder.cluster"
		}
		cfg.AlertURL = fmt.Sprintf("https://http2k.%s/rbdata/%s/rb_event", domain, state.UUID)

		// Extract manager IP from ManagerURL and update /etc/hosts
		u, err := url.Parse(cfg.ManagerURL)
		if err == nil {
			managerHost := u.Hostname()
			hostsEntry := fmt.Sprintf("%s http2k.%s\n", managerHost, domain)
			f, err := os.OpenFile("/etc/hosts", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
			if err == nil {
				f.WriteString(hostsEntry)
				f.Close()
				fmt.Printf("[+] Updated /etc/hosts: %s", hostsEntry)
			}
		}
	}

	addr := fmt.Sprintf("%s:%d", cfg.Target, cfg.Port)
	udpConn, _ := net.Dial("udp", addr)
	client := getClient(cfg.Insecure)
	localIP := getLocalIP()

	fmt.Printf("[+] Starting alert generation (%d/min). AlertURL: %s\n", cfg.Rate, cfg.AlertURL)

	count := 0
	for {
		s := pickScenario(cfg.Scenarios)
		msg := s.Messages[nrand(len(s.Messages))]
		srcIP := getRandomIP(s.SrcCIDR)
		dstIP := getRandomIP(s.DstCIDR)
		srcPort := nrand(64511) + 1024
		dstPort := 80

		alert := SnortAlert{
			Timestamp:      time.Now().Unix(),
			SensorIDSnort:  0,
			Action:         "alert",
			SigGenerator:   136,
			SigID:          s.SigID,
			Rev:            1,
			Priority:       "medium",
			Classification: "Potentially Bad Traffic",
			Msg:            msg,
			Payload:        "-",
			L4ProtoName:    "tcp",
			L4Proto:        6,
			EthSrc:         "00:11:22:33:44:55",
			EthDst:         "66:77:88:99:AA:BB",
			EthSrcVendor:   "Cisco Systems, Inc",
			EthDstVendor:   "Cisco Systems, Inc",
			EthType:        33024,
			Vlan:           2,
			VlanName:       "2",
			VlanPriority:   0,
			VlanDrop:       0,
			EthLength:      0,
			EthLengthRange: "0(0-64]",
			SrcPort:        srcPort,
			SrcPortName:    fmt.Sprintf("%d", srcPort),
			DstPort:        dstPort,
			DstPortName:    "http",
			SrcAsNum:       49938442,
			Src:            srcIP,
			SrcName:        srcIP,
			DstAsNum:       "780750633",
			DstName:        dstIP,
			Dst:            dstIP,
			TTL:            63,
			TOS:            0,
			ID:             0,
			IPLen:          60,
			IPLenRange:     "[32-64)",
			DgmLen:         60,
			TcpSeq:         uint32(nrand(4294967295)),
			TcpAck:         uint32(nrand(4294967295)),
			TcpLen:         40,
			TcpWindow:      65160,
			TcpFlags:       "***A**S*",
			SensorType:     "ips",
			SensorIP:       localIP,
			SensorUUID:     state.UUID,
			SensorName:     state.Nodename,
		}

		if alert.SensorName == "" {
			alert.SensorName = "ips-mock-agent"
		}

		alertJSON, _ := json.Marshal(alert)
		if count%5 == 0 {
			fmt.Printf("[DEBUG] Payload: %s\n", string(alertJSON))
		}

		// Send via HTTPS if URL provided
		if cfg.AlertURL != "" {
			resp, err := client.Post(cfg.AlertURL, "application/json", bytes.NewBuffer(alertJSON))
			if err != nil {
				fmt.Printf("[-] Error sending HTTPS alert: %v\n", err)
			} else {
				resp.Body.Close()
				fmt.Printf("[+] Sent HTTPS alert: %s\n", msg)
			}
		}

		// Periodic heartbeat/verify to keep manager status active
		count++
		if count%10 == 0 && cfg.ManagerURL != "" {
			fmt.Println("[*] Checking for new configuration (heartbeat)...")
			checkIn(cfg, state)
			saveState(*stateFile, state)
		}

		// Fallback/Dual-send via Syslog
		if udpConn != nil {
			syslogMsg := fmt.Sprintf("<134>snort: %s\n", string(alertJSON))
			udpConn.Write([]byte(syslogMsg))
			if cfg.AlertURL == "" { fmt.Printf("[+] Sent Syslog alert: %s\n", msg) }
		}

		if cfg.Rate > 0 {
			time.Sleep(time.Minute / time.Duration(cfg.Rate))
		} else {
			time.Sleep(10 * time.Second)
		}
	}
}
