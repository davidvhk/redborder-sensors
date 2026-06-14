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
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const VERSION = "v1.13 (2026-06-14)"

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
	Port         int    `json:"port"`
	Rate         int    `json:"rate"`
	Insecure     bool   `json:"insecure"`
	Domain       string `json:"domain"`
	Verbose      bool   `json:"verbose"`
	SensorType   int    `json:"type"`
}

// NetFlow v5 structures
type NetFlowV5Header struct {
	Version uint16; Count uint16; SysUptime uint32; UnixSecs uint32; UnixNanos uint32; FlowSequence uint32; EngineType uint8; EngineID uint8; SamplingInterval uint16
}

type NetFlowV5Record struct {
	SrcAddr [4]byte; DstAddr [4]byte; NextHop [4]byte; Input uint16; Output uint16; DPkts uint32; DOctets uint32; First uint32; Last uint32; SrcPort uint16; DstPort uint16; Pad1 uint8; TCPFlags uint8; Prot uint8; Tos uint8; SrcAs uint16; DstAs uint16; SrcMask uint8; DstMask uint8; Pad2 uint16
}

type NetFlowV9Header struct {
	Version uint16; Count uint16; SysUptime uint32; UnixSecs uint32; FlowSequence uint32; SourceID uint32
}

type IPFIXHeader struct {
	Version uint16; Length uint16; ExportTime uint32; SequenceNumber uint32; DomainID uint32
}

type NetField struct { Type uint16; Len uint16 }
type NetTemplate struct { Fields []NetField }

var (
	v9Templates    = make(map[uint32]map[uint16]NetTemplate)
	ipfixTemplates = make(map[uint32]map[uint16]NetTemplate)
)

// Standard Redborder Flow JSON
type RedborderFlow struct {
	Timestamp      int64  `json:"timestamp"`
	SensorUUID     string `json:"sensor_uuid"`
	SensorName     string `json:"sensor_name"`
	SensorType     string `json:"sensor_type"`
	LanIP          string `json:"lan_ip"`
	WanIP          string `json:"wan_ip"`
	LanL4Port      uint16 `json:"lan_l4_port"`
	WanL4Port      uint16 `json:"wan_l4_port"`
	L4Proto        uint8  `json:"l4_proto"`
	Bytes          uint32 `json:"bytes"`
	Pkts           uint32 `json:"pkts"`
	IPProtocolVer  int    `json:"ip_protocol_version"`
}

// Standard Redborder Vault JSON
type RedborderVault struct {
	Timestamp  int64  `json:"timestamp"`
	SensorUUID string `json:"sensor_uuid"`
	SensorName string `json:"sensor_name"`
	SensorType string `json:"sensor_type"`
	Msg        string `json:"msg"`
	SrcIP      string `json:"src_ip"`
}

func generateUUID() string {
	b := make([]byte, 16); rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func loadState(path string) (*State, error) {
	data, err := os.ReadFile(path); if err != nil { return nil, err }
	var state State; if err := json.Unmarshal(data, &state); err != nil { return nil, err }
	return &state, nil
}

func saveState(path string, state *State) error {
	data, err := json.MarshalIndent(state, "", "  "); if err != nil { return err }
	return os.WriteFile(path, data, 0644)
}

func getClient(insecure bool) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}},
	}
}

func register(cfg Config, state *State) error {
	client := getClient(cfg.Insecure)
	payload := map[string]interface{}{"order": "register", "type": cfg.SensorType, "hash": state.Hash, "cpus": 2, "memory": 4194304}
	data, _ := json.Marshal(payload)
	fmt.Printf("[*] Sending registration request to %s...\n", cfg.ManagerURL)
	resp, err := client.Post(cfg.ManagerURL, "application/json", bytes.NewBuffer(data)); if err != nil { return err }
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated { return fmt.Errorf("manager returned %d: %s", resp.StatusCode, string(body)) }
	var res map[string]interface{}; json.Unmarshal(body, &res)
	if status, ok := res["status"].(string); ok && (status == "registered" || status == "claimed") {
		if uuid, ok := res["uuid"].(string); ok { state.UUID = uuid }
		if nodename, ok := res["nodename"].(string); ok { state.Nodename = nodename }
		if priv, ok := res["private_key"].(string); ok { state.PrivateKey = priv } else if cert, ok := res["cert"].(string); ok {
			var unquoted string; if err := json.Unmarshal([]byte(cert), &unquoted); err == nil { state.PrivateKey = unquoted } else { state.PrivateKey = cert }
		}
		if client, ok := res["client_name"].(string); ok { state.ClientName = client } else if state.Nodename != "" { state.ClientName = state.Nodename }
		state.Status = status; return nil
	}
	return fmt.Errorf("unexpected manager response status: %s", string(body))
}

func verify(cfg Config, state *State) error {
	client := getClient(cfg.Insecure)
	payload := map[string]interface{}{"order": "verify", "hash": state.Hash, "uuid": state.UUID}
	data, _ := json.Marshal(payload)
	resp, err := client.Post(cfg.ManagerURL, "application/json", bytes.NewBuffer(data)); if err != nil { return err }
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body); var res map[string]interface{}; json.Unmarshal(body, &res)
	if status, ok := res["status"].(string); ok {
		if nodename, ok := res["nodename"].(string); ok { state.Nodename = nodename }
		if priv, ok := res["private_key"].(string); ok { state.PrivateKey = priv } else if cert, ok := res["cert"].(string); ok {
			var unquoted string; if err := json.Unmarshal([]byte(cert), &unquoted); err == nil { state.PrivateKey = unquoted } else { state.PrivateKey = cert }
		}
		if client, ok := res["client_name"].(string); ok { state.ClientName = client } else if state.Nodename != "" { state.ClientName = state.Nodename }
		state.Status = status; return nil
	}
	return fmt.Errorf("verification failed: %s", string(body))
}

func signChefRequest(req *http.Request, clientName string, privateKeyPEM string) error {
	if privateKeyPEM == "" { return nil }
	block, _ := pem.Decode([]byte(privateKeyPEM)); if block == nil { return fmt.Errorf("failed to decode private key PEM") }
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); if err != nil { return fmt.Errorf("failed to parse private key: %v", err) }
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	path := req.URL.Path; if path == "" { path = "/" }
	hPath := sha1.New(); hPath.Write([]byte(path)); hashedPath := base64.StdEncoding.EncodeToString(hPath.Sum(nil))
	var body []byte; if req.Body != nil { body, _ = io.ReadAll(req.Body); req.Body = io.NopCloser(bytes.NewBuffer(body)) }
	hBody := sha1.New(); hBody.Write(body); hashedBody := base64.StdEncoding.EncodeToString(hBody.Sum(nil))
	canonicalReq := fmt.Sprintf("Method:%s\nHashed Path:%s\nX-Ops-Content-Hash:%s\nX-Ops-Timestamp:%s\nX-Ops-UserId:%s", req.Method, hashedPath, hashedBody, timestamp, clientName)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.Hash(0), []byte(canonicalReq)); if err != nil { return fmt.Errorf("failed to sign: %v", err) }
	sigBase64 := base64.StdEncoding.EncodeToString(signature)
	req.Header.Set("X-Ops-Sign", "version=1.0"); req.Header.Set("X-Ops-UserId", clientName); req.Header.Set("X-Ops-Timestamp", timestamp); req.Header.Set("X-Ops-Content-Hash", hashedBody); req.Header.Set("Accept", "application/json")
	for i := 0; i*60 < len(sigBase64); i++ {
		end := (i + 1) * 60; if end > len(sigBase64) { end = len(sigBase64) }
		req.Header.Set(fmt.Sprintf("X-Ops-Authorization-%d", i+1), sigBase64[i*60:end])
	}
	return nil
}

func checkIn(cfg Config, state *State) error {
	client := getClient(cfg.Insecure)
	baseURL := strings.TrimSuffix(cfg.ManagerURL, "/"); baseURL = strings.TrimSuffix(baseURL, "/register")
	if strings.HasSuffix(baseURL, "/sensors") { baseURL = strings.TrimSuffix(baseURL, "/sensors") + "/ips" }
	checkInURL := fmt.Sprintf("%s/has_new_config?sensor[uuid]=%s", baseURL, state.UUID)
	req, _ := http.NewRequest("GET", checkInURL, nil)
	clientName := state.ClientName; if clientName == "" && cfg.APIAccessKey != "" { clientName = cfg.APIAccessKey }
	if state.PrivateKey != "" && clientName != "" { signChefRequest(req, clientName, state.PrivateKey) }
	resp, err := client.Do(req); if err != nil { return err }
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified { return nil }
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK { fmt.Printf("[!] NEW CONFIGURATION DETECTED! Ruleset UUID: %s\n", string(body)); return nil }
	return fmt.Errorf("check-in failed with status %d: %s", resp.StatusCode, string(body))
}

func decodeUint(b []byte) uint32 {
	switch len(b) {
	case 1: return uint32(b[0])
	case 2: return uint32(binary.BigEndian.Uint16(b))
	case 4: return binary.BigEndian.Uint32(b)
	}
	return 0
}

func templateSize(tmpl NetTemplate) int {
	size := 0
	for _, f := range tmpl.Fields { size += int(f.Len) }
	return size
}

func handleNetFlowV5(data []byte, cfg Config, state *State, httpClient *http.Client, endpoint string) {
	reader := bytes.NewReader(data)
	var header NetFlowV5Header; if err := binary.Read(reader, binary.BigEndian, &header); err != nil { return }
	if header.Version != 5 { return }
	for i := 0; i < int(header.Count); i++ {
		var record NetFlowV5Record; if err := binary.Read(reader, binary.BigEndian, &record); err != nil { break }
		flow := RedborderFlow{
			Timestamp: time.Now().Unix(), SensorUUID: state.UUID, SensorName: state.Nodename, SensorType: "proxy",
			LanIP: net.IP(record.SrcAddr[:]).String(), WanIP: net.IP(record.DstAddr[:]).String(),
			LanL4Port: record.SrcPort, WanL4Port: record.DstPort, L4Proto: record.Prot, Bytes: record.DOctets, Pkts: record.DPkts, IPProtocolVer: 4,
		}
		payload, _ := json.Marshal(flow)
		resp, err := httpClient.Post(endpoint, "application/json", bytes.NewBuffer(payload)); if err == nil { resp.Body.Close() }
	}
}

func handleNetFlowV9(data []byte, cfg Config, state *State, httpClient *http.Client, endpoint string) {
	reader := bytes.NewReader(data)
	var header NetFlowV9Header; if err := binary.Read(reader, binary.BigEndian, &header); err != nil { return }
	for reader.Len() >= 4 {
		var flowSetID, length uint16
		binary.Read(reader, binary.BigEndian, &flowSetID); binary.Read(reader, binary.BigEndian, &length)
		if length < 4 { break }
		payload := make([]byte, length-4); reader.Read(payload)
		if flowSetID == 0 { // Template FlowSet
			pReader := bytes.NewReader(payload)
			for pReader.Len() >= 4 {
				var templateID, fieldCount uint16
				binary.Read(pReader, binary.BigEndian, &templateID); binary.Read(pReader, binary.BigEndian, &fieldCount)
				var tmpl NetTemplate
				for i := 0; i < int(fieldCount); i++ {
					var fieldType, fieldLen uint16
					binary.Read(pReader, binary.BigEndian, &fieldType); binary.Read(pReader, binary.BigEndian, &fieldLen)
					tmpl.Fields = append(tmpl.Fields, NetField{fieldType, fieldLen})
				}
				if v9Templates[header.SourceID] == nil { v9Templates[header.SourceID] = make(map[uint16]NetTemplate) }
				v9Templates[header.SourceID][templateID] = tmpl
			}
		} else if flowSetID > 255 { // Data FlowSet
			tmpl, ok := v9Templates[header.SourceID][flowSetID]
			if !ok { continue }
			pReader := bytes.NewReader(payload); tSize := templateSize(tmpl)
			for pReader.Len() >= tSize {
				flow := RedborderFlow{Timestamp: time.Now().Unix(), SensorUUID: state.UUID, SensorName: state.Nodename, SensorType: "proxy", IPProtocolVer: 4}
				for _, f := range tmpl.Fields {
					val := make([]byte, f.Len); pReader.Read(val)
					switch f.Type {
					case 1: flow.Bytes = decodeUint(val)
					case 2: flow.Pkts = decodeUint(val)
					case 4: flow.L4Proto = uint8(decodeUint(val))
					case 7: flow.LanL4Port = uint16(decodeUint(val))
					case 8:
						flow.LanIP = net.IP(val).String()
						flow.IPProtocolVer = 4
					case 12:
						flow.WanIP = net.IP(val).String()
						flow.IPProtocolVer = 4
					case 27:
						flow.LanIP = net.IP(val).String()
						flow.IPProtocolVer = 6
					case 28:
						flow.WanIP = net.IP(val).String()
						flow.IPProtocolVer = 6
					case 11: flow.WanL4Port = uint16(decodeUint(val))
					}
				}
				payloadJSON, _ := json.Marshal(flow)
				resp, err := httpClient.Post(endpoint, "application/json", bytes.NewBuffer(payloadJSON)); if err == nil { resp.Body.Close() }
			}
		}
	}
}

func handleIPFIX(data []byte, cfg Config, state *State, httpClient *http.Client, endpoint string) {
	reader := bytes.NewReader(data)
	var header IPFIXHeader; if err := binary.Read(reader, binary.BigEndian, &header); err != nil { return }
	for reader.Len() >= 4 {
		var setID, length uint16
		binary.Read(reader, binary.BigEndian, &setID); binary.Read(reader, binary.BigEndian, &length)
		if length < 4 { break }
		payload := make([]byte, length-4); reader.Read(payload)
		if setID == 2 { // Template Set
			pReader := bytes.NewReader(payload)
			for pReader.Len() >= 4 {
				var templateID, fieldCount uint16
				binary.Read(pReader, binary.BigEndian, &templateID); binary.Read(pReader, binary.BigEndian, &fieldCount)
				var tmpl NetTemplate
				for i := 0; i < int(fieldCount); i++ {
					var fieldType, fieldLen uint16
					binary.Read(pReader, binary.BigEndian, &fieldType); binary.Read(pReader, binary.BigEndian, &fieldLen)
					tmpl.Fields = append(tmpl.Fields, NetField{fieldType, fieldLen})
				}
				if ipfixTemplates[header.DomainID] == nil { ipfixTemplates[header.DomainID] = make(map[uint16]NetTemplate) }
				ipfixTemplates[header.DomainID][templateID] = tmpl
			}
		} else if setID > 255 { // Data Set
			tmpl, ok := ipfixTemplates[header.DomainID][setID]
			if !ok { continue }
			pReader := bytes.NewReader(payload); tSize := templateSize(tmpl)
			for pReader.Len() >= tSize {
				flow := RedborderFlow{Timestamp: time.Now().Unix(), SensorUUID: state.UUID, SensorName: state.Nodename, SensorType: "proxy", IPProtocolVer: 4}
				for _, f := range tmpl.Fields {
					val := make([]byte, f.Len); pReader.Read(val)
					switch f.Type {
					case 1: flow.Bytes = decodeUint(val)
					case 2: flow.Pkts = decodeUint(val)
					case 4: flow.L4Proto = uint8(decodeUint(val))
					case 7: flow.LanL4Port = uint16(decodeUint(val))
					case 8:
						flow.LanIP = net.IP(val).String()
						flow.IPProtocolVer = 4
					case 12:
						flow.WanIP = net.IP(val).String()
						flow.IPProtocolVer = 4
					case 27:
						flow.LanIP = net.IP(val).String()
						flow.IPProtocolVer = 6
					case 28:
						flow.WanIP = net.IP(val).String()
						flow.IPProtocolVer = 6
					case 11: flow.WanL4Port = uint16(decodeUint(val))
					}
				}
				payloadJSON, _ := json.Marshal(flow)
				resp, err := httpClient.Post(endpoint, "application/json", bytes.NewBuffer(payloadJSON)); if err == nil { resp.Body.Close() }
			}
		}
	}
}

func handleSFlow(data []byte, cfg Config, state *State, httpClient *http.Client, endpoint string) {
	reader := bytes.NewReader(data)
	var version, ipVersion uint32
	binary.Read(reader, binary.BigEndian, &version); if version != 5 { return }
	binary.Read(reader, binary.BigEndian, &ipVersion)
	var agentIP []byte; if ipVersion == 1 { agentIP = make([]byte, 4) } else { agentIP = make([]byte, 16) }
	reader.Read(agentIP)
	var subAgentID, sequenceNumber, uptime, numSamples uint32
	binary.Read(reader, binary.BigEndian, &subAgentID); binary.Read(reader, binary.BigEndian, &sequenceNumber); binary.Read(reader, binary.BigEndian, &uptime); binary.Read(reader, binary.BigEndian, &numSamples)

	for i := 0; i < int(numSamples); i++ {
		var sampleFormat, sampleLength uint32
		binary.Read(reader, binary.BigEndian, &sampleFormat); binary.Read(reader, binary.BigEndian, &sampleLength)
		if sampleFormat != 1 { reader.Seek(int64(sampleLength), io.SeekCurrent); continue } // Not a Flow Sample

		sReader := io.LimitReader(reader, int64(sampleLength))
		var seq, sourceID, samplingRate, samplePool, drops, inputIf, outputIf, numRecords uint32
		binary.Read(sReader, binary.BigEndian, &seq); binary.Read(sReader, binary.BigEndian, &sourceID); binary.Read(sReader, binary.BigEndian, &samplingRate); binary.Read(sReader, binary.BigEndian, &samplePool); binary.Read(sReader, binary.BigEndian, &drops); binary.Read(sReader, binary.BigEndian, &inputIf); binary.Read(sReader, binary.BigEndian, &outputIf); binary.Read(sReader, binary.BigEndian, &numRecords)

		for j := 0; j < int(numRecords); j++ {
			var recFormat, recLength uint32
			binary.Read(sReader, binary.BigEndian, &recFormat); binary.Read(sReader, binary.BigEndian, &recLength)
			if recFormat != 1 { // Not a Sampled Header
				io.CopyN(io.Discard, sReader, int64(recLength))
				continue
			}
			var proto, frameLen, stripped uint32
			binary.Read(sReader, binary.BigEndian, &proto); binary.Read(sReader, binary.BigEndian, &frameLen); binary.Read(sReader, binary.BigEndian, &stripped)
			var headerLen uint32; binary.Read(sReader, binary.BigEndian, &headerLen)
			header := make([]byte, headerLen); io.ReadFull(sReader, header)
			// Skip padding
			padding := (4 - (headerLen % 4)) % 4
			io.CopyN(io.Discard, sReader, int64(padding))

			if proto == 1 && len(header) >= 34 { // Ethernet + IPv4
				ethType := binary.BigEndian.Uint16(header[12:14])
				if ethType == 0x0800 { // IPv4
					ipHeader := header[14:]
					proto := ipHeader[9]; srcIP := net.IP(ipHeader[12:16]); dstIP := net.IP(ipHeader[16:20])
					ihL := int(ipHeader[0]&0x0f) * 4; transport := ipHeader[ihL:]
					var sp, dp uint16
					if (proto == 6 || proto == 17) && len(transport) >= 4 {
						sp = binary.BigEndian.Uint16(transport[0:2]); dp = binary.BigEndian.Uint16(transport[2:4])
					}
					flow := RedborderFlow{
						Timestamp: time.Now().Unix(), SensorUUID: state.UUID, SensorName: state.Nodename, SensorType: "sflow",
						LanIP: srcIP.String(), WanIP: dstIP.String(), LanL4Port: sp, WanL4Port: dp, L4Proto: proto,
						Bytes: frameLen, Pkts: 1, IPProtocolVer: 4,
					}
					payload, _ := json.Marshal(flow)
					resp, err := httpClient.Post(endpoint, "application/json", bytes.NewBuffer(payload)); if err == nil { resp.Body.Close() }
				} else if ethType == 0x86dd && len(header) >= 54 { // IPv6
					ipHeader := header[14:]
					proto := ipHeader[6]; srcIP := net.IP(ipHeader[8:24]); dstIP := net.IP(ipHeader[24:40])
					transport := ipHeader[40:]
					var sp, dp uint16
					if (proto == 6 || proto == 17) && len(transport) >= 4 {
						sp = binary.BigEndian.Uint16(transport[0:2]); dp = binary.BigEndian.Uint16(transport[2:4])
					}
					flow := RedborderFlow{
						Timestamp: time.Now().Unix(), SensorUUID: state.UUID, SensorName: state.Nodename, SensorType: "sflow",
						LanIP: srcIP.String(), WanIP: dstIP.String(), LanL4Port: sp, WanL4Port: dp, L4Proto: proto,
						Bytes: frameLen, Pkts: 1, IPProtocolVer: 6,
					}
					payload, _ := json.Marshal(flow)
					resp, err := httpClient.Post(endpoint, "application/json", bytes.NewBuffer(payload)); if err == nil { resp.Body.Close() }
				}
			}
		}
		// Consume any remaining data in sReader (alignment/etc)
		io.Copy(io.Discard, sReader)
	}
}

func handleSyslog(data []byte, remoteAddr net.Addr, cfg Config, state *State, httpClient *http.Client, endpoint string) {
	vault := RedborderVault{
		Timestamp: time.Now().Unix(), SensorUUID: state.UUID, SensorName: state.Nodename, SensorType: "proxy",
		Msg: string(data), SrcIP: strings.Split(remoteAddr.String(), ":")[0],
	}
	payload, _ := json.Marshal(vault)
	resp, err := httpClient.Post(endpoint, "application/json", bytes.NewBuffer(payload)); if err == nil { resp.Body.Close() }
}

func startUDPListener(port int, mode string, cfg Config, state *State, httpClient *http.Client) {
	laddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	conn, err := net.ListenUDP("udp", laddr); if err != nil { fmt.Printf("[-] Error listening on UDP %d: %v\n", port, err); return }
	defer conn.Close()
	fmt.Printf("[+] Listening for %s on UDP %d...\n", mode, port)
	domain := cfg.Domain; if domain == "" { domain = "redborder.cluster" }
	topic := "rb_flow"
	if mode == "syslog" {
		topic = "rb_vault"
	} else if mode == "sflow" {
		topic = "sflow"
	}
	endpoint := fmt.Sprintf("https://http2k.%s/rbdata/%s/%s", domain, state.UUID, topic)
	buf := make([]byte, 65535)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf); if err != nil { continue }
		packet := buf[:n]
		switch mode {
		case "netflow":
			if len(packet) < 2 { continue }
			version := binary.BigEndian.Uint16(packet[:2])
			switch version {
			case 5: handleNetFlowV5(packet, cfg, state, httpClient, endpoint)
			case 9: handleNetFlowV9(packet, cfg, state, httpClient, endpoint)
			case 10: handleIPFIX(packet, cfg, state, httpClient, endpoint)
			}
		case "sflow":
			handleSFlow(packet, cfg, state, httpClient, endpoint)
		case "syslog": handleSyslog(packet, remoteAddr, cfg, state, httpClient, endpoint)
		}
	}
}

func main() {
	cP := flag.String("config", "", "JSON config file"); mU := flag.String("manager", "", "Manager registration URL"); aK := flag.String("api-key", "", "API Access Key"); rateF := flag.Int("rate", 4, "Heartbeat rate in minutes"); inS := flag.Bool("insecure", true, "Skip TLS verification"); domF := flag.String("domain", "redborder.cluster", "Redborder domain"); verbF := flag.Bool("v", false, "Enable verbose logging"); sT := flag.Int("type", 31, "Sensor type")
	dS := "/sensor-data/proxy-state.json"; if os.Getenv("SENSOR_NAME") != "" { dS = fmt.Sprintf("/sensor-data/proxy-state-%s.json", os.Getenv("SENSOR_NAME")) }
	sF := flag.String("state", dS, "Path to state file"); flag.Parse()
	fmt.Printf("[+] Redborder Proxy Agent %s\n", VERSION)
	cfg := Config{ManagerURL: *mU, APIAccessKey: *aK, Rate: *rateF, Insecure: *inS, Domain: *domF, Verbose: *verbF, SensorType: *sT}
	if *cP != "" { f, err := os.ReadFile(*cP); if err == nil { json.Unmarshal(f, &cfg) } }
	state, err := loadState(*sF); if err != nil { state = &State{Hash: generateUUID(), Status: "unregistered"} }
	if cfg.ManagerURL != "" {
		for state.Status != "claimed" {
			if state.Status == "unregistered" {
				if err := register(cfg, state); err == nil { fmt.Printf("[+] Registered! Manager UUID: %s. Use this to CLAIM: %s\n", state.UUID, state.Hash); saveState(*sF, state) } else { time.Sleep(10 * time.Second); continue }
			}
			if state.Status == "registered" {
				if err := verify(cfg, state); err == nil { saveState(*sF, state) } else { time.Sleep(10 * time.Second); continue }
			}
		}
		u, _ := url.Parse(cfg.ManagerURL); d := cfg.Domain; if d == "" { d = "redborder.cluster" }
		hostsEntry := fmt.Sprintf("%s http2k.%s\n", u.Hostname(), d); f, err := os.OpenFile("/etc/hosts", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644); if err == nil { f.WriteString(hostsEntry); f.Close() }
	}
	sensorName := state.Nodename; if sensorName == "" { sensorName = os.Getenv("SENSOR_NAME") }
	fmt.Printf("[+] Proxy Agent active. UUID: %s. Nodename: %s\n", state.UUID, sensorName)
	httpClient := getClient(cfg.Insecure)
	go startUDPListener(2055, "netflow", cfg, state, httpClient)
	go startUDPListener(6343, "sflow", cfg, state, httpClient)
	go startUDPListener(514, "syslog", cfg, state, httpClient)
	checkIn(cfg, state)
	ticker := time.NewTicker(time.Duration(cfg.Rate) * time.Minute)
	for { select { case <-ticker.C: checkIn(cfg, state) } }
}
