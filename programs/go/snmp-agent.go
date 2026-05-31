package main

// Author: David Vanhoucke <dvanhoucke@redborder.com>

import (
	"encoding/asn1"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

const AgentVersion = "2.1"

// SNMP basic structures
type SNMPMessage struct {
	Version   int
	Community []byte
	Data      asn1.RawValue
}

type PDUType struct {
	RequestID        int
	ErrorStatus      int
	ErrorIndex       int
	VariableBindings []VarBind
}

type VarBind struct {
	Name  asn1.ObjectIdentifier
	Value asn1.RawValue
}

type OIDConfig struct {
	OID   string `json:"oid"`
	Type  string `json:"type"` // string, integer, timeticks, oid, cpu, mem_free, mem_used
	Value string `json:"value,omitempty"`
	Min   int    `json:"min,omitempty"`
	Max   int    `json:"max,omitempty"`
}

type Config struct {
	Community string      `json:"community"`
	OIDs      []OIDConfig `json:"oids"`
}

var (
	currentConfig Config
	orderedOIDs   []asn1.ObjectIdentifier
	oidMap        map[string]OIDConfig
	startTime     = time.Now()
)

func parseOID(s string) asn1.ObjectIdentifier {
	parts := strings.Split(s, ".")
	var res asn1.ObjectIdentifier
	for _, p := range parts {
		if p == "" { continue }
		var v int
		fmt.Sscanf(p, "%d", &v)
		res = append(res, v)
	}
	return res
}

func loadConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil { return err }
	if err := json.Unmarshal(data, &currentConfig); err != nil { return err }

	oidMap = make(map[string]OIDConfig)
	orderedOIDs = nil
	for _, oc := range currentConfig.OIDs {
		oid := parseOID(oc.OID)
		orderedOIDs = append(orderedOIDs, oid)
		oidMap[oid.String()] = oc
	}

	// Sort OIDs for GET-NEXT/GET-BULK
	sort.Slice(orderedOIDs, func(i, j int) bool {
		return isLess(orderedOIDs[i], orderedOIDs[j])
	})

	return nil
}

func getOIDValue(oid asn1.ObjectIdentifier) (asn1.RawValue, bool) {
	oc, found := oidMap[oid.String()]
	if !found { return asn1.RawValue{}, false }

	// Helper for random in range
	randRange := func(min, max, defMin, defMax int) int {
		if max <= min {
			return defMin + rand.Intn(defMax-defMin+1)
		}
		return min + rand.Intn(max-min+1)
	}

	switch oc.Type {
	case "string":
		val, _ := asn1.Marshal([]byte(oc.Value))
		return asn1.RawValue{FullBytes: val}, true
	case "integer":
		var v int
		fmt.Sscanf(oc.Value, "%d", &v)
		val, _ := asn1.Marshal(v)
		return asn1.RawValue{FullBytes: val}, true
	case "timeticks":
		uptime := uint32(time.Since(startTime).Milliseconds() / 10)
		val, _ := asn1.Marshal(uptime)
		if len(val) > 0 { val[0] = 0x43 } else { val = []byte{0x43, 0x01, 0x00} }
		return asn1.RawValue{FullBytes: val}, true
	case "oid":
		target := parseOID(oc.Value)
		val, _ := asn1.Marshal(target)
		return asn1.RawValue{FullBytes: val}, true
	case "cpu":
		load := randRange(oc.Min, oc.Max, 5, 40)
		val, _ := asn1.Marshal(load)
		return asn1.RawValue{FullBytes: val}, true
	case "mem_free":
		mem := randRange(oc.Min, oc.Max, 512000, 2048000)
		val, _ := asn1.Marshal(mem)
		return asn1.RawValue{FullBytes: val}, true
	case "mem_used":
		mem := randRange(oc.Min, oc.Max, 1024000, 4096000)
		val, _ := asn1.Marshal(mem)
		return asn1.RawValue{FullBytes: val}, true
	}

	return asn1.RawValue{}, false
}

func getNextOID(oid asn1.ObjectIdentifier) (asn1.ObjectIdentifier, bool) {
	for i, o := range orderedOIDs {
		if isLess(oid, o) { return o, true }
		if oid.Equal(o) {
			if i+1 < len(orderedOIDs) { return orderedOIDs[i+1], true }
			break
		}
	}
	return nil, false
}

func isLess(a, b asn1.ObjectIdentifier) bool {
	l := len(a)
	if len(b) < l { l = len(b) }
	for i := 0; i < l; i++ {
		if a[i] < b[i] { return true }
		if a[i] > b[i] { return false }
	}
	return len(a) < len(b)
}

func main() {
	configPath := flag.String("config", "", "Path to JSON configuration file")
	flag.Parse()

	if *configPath != "" {
		if err := loadConfig(*configPath); err != nil {
			fmt.Printf("[-] Error loading config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] Loaded %d OIDs from %s\n", len(orderedOIDs), *configPath)
	} else {
		// Default OIDs if no config provided
		currentConfig.Community = "public"
		currentConfig.OIDs = []OIDConfig{
			{OID: "1.3.6.1.2.1.1.1.0", Type: "string", Value: "Cisco IOS Software, C2960 Software, v2.1-ConfigDriven"},
			{OID: "1.3.6.1.2.1.1.2.0", Type: "oid", Value: "1.3.6.1.4.1.9.1.1208"},
			{OID: "1.3.6.1.2.1.1.3.0", Type: "timeticks"},
			{OID: "1.3.6.1.2.1.1.5.0", Type: "string", Value: "cisco-switch-sandbox"},
		}
		loadConfigFromMemory()
	}

	addr, err := net.ResolveUDPAddr("udp", ":161")
	if err != nil { fmt.Printf("Error resolving address: %v\n", err); os.Exit(1) }
	conn, err := net.ListenUDP("udp", addr)
	if err != nil { fmt.Printf("Error listening on UDP 161: %v\n", err); os.Exit(1) }
	defer conn.Close()

	fmt.Printf("[+] SNMP Agent mimicking Cisco 2960 (v%s) started on :161\n", AgentVersion)
	fmt.Printf("[+] Community: %s\n", currentConfig.Community)

	buf := make([]byte, 1500)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil { continue }
		handlePacket(conn, remoteAddr, buf[:n])
	}
}

func loadConfigFromMemory() {
	oidMap = make(map[string]OIDConfig)
	orderedOIDs = nil
	for _, oc := range currentConfig.OIDs {
		oid := parseOID(oc.OID)
		orderedOIDs = append(orderedOIDs, oid)
		oidMap[oid.String()] = oc
	}
	sort.Slice(orderedOIDs, func(i, j int) bool { return isLess(orderedOIDs[i], orderedOIDs[j]) })
}

func handlePacket(conn *net.UDPConn, addr *net.UDPAddr, data []byte) {
	var msg SNMPMessage
	_, err := asn1.Unmarshal(data, &msg)
	if err != nil { return }
	if msg.Version > 1 { return }

	// Community String Validation
	if string(msg.Community) != currentConfig.Community {
		fmt.Printf("[!] Unauthorized access attempt with community: %s\n", string(msg.Community))
		return
	}

	pduRaw := msg.Data.FullBytes
	if len(pduRaw) == 0 { return }
	originalTag := pduRaw[0]
	pduRaw[0] = 0x30 

	var pdu PDUType
	_, err = asn1.Unmarshal(pduRaw, &pdu)
	if err != nil { return }

	responseBindings := []VarBind{}

	if originalTag == 0xA5 { // GET-BULK
		nonRepeaters := pdu.ErrorStatus
		maxRepetitions := pdu.ErrorIndex
		if nonRepeaters < 0 { nonRepeaters = 0 }
		if maxRepetitions < 0 { maxRepetitions = 0 }

		for i := 0; i < len(pdu.VariableBindings); i++ {
			reqOID := pdu.VariableBindings[i].Name
			if i < nonRepeaters {
				targetOID, found := getNextOID(reqOID)
				var val asn1.RawValue
				if found { val, _ = getOIDValue(targetOID) } else { val = asn1.RawValue{FullBytes: []byte{0x82, 0x00}}; targetOID = reqOID }
				responseBindings = append(responseBindings, VarBind{Name: targetOID, Value: val})
			} else {
				currentOID := reqOID
				for r := 0; r < maxRepetitions; r++ {
					nextOID, found := getNextOID(currentOID)
					var val asn1.RawValue
					if !found {
						val = asn1.RawValue{FullBytes: []byte{0x82, 0x00}}
						responseBindings = append(responseBindings, VarBind{Name: currentOID, Value: val})
						break
					}
					val, _ = getOIDValue(nextOID)
					responseBindings = append(responseBindings, VarBind{Name: nextOID, Value: val})
					currentOID = nextOID
				}
			}
		}
	} else {
		for _, bind := range pdu.VariableBindings {
			reqOID := bind.Name
			var targetOID asn1.ObjectIdentifier
			var val asn1.RawValue
			var found bool

			if originalTag == 0xA1 { // GET-NEXT
				targetOID, found = getNextOID(reqOID)
				if found { val, _ = getOIDValue(targetOID) }
			} else { // GET (0xA0)
				targetOID = reqOID
				val, found = getOIDValue(targetOID)
			}

			if !found {
				tag := byte(0x82) // endOfMibView
				if originalTag == 0xA0 { tag = 0x80 } // noSuchObject
				val = asn1.RawValue{FullBytes: []byte{tag, 0x00}}
				targetOID = reqOID
			}
			responseBindings = append(responseBindings, VarBind{Name: targetOID, Value: val})
		}
	}

	respPDU := PDUType{RequestID: pdu.RequestID, ErrorStatus: 0, ErrorIndex: 0, VariableBindings: responseBindings}
	pduBytes, _ := asn1.Marshal(respPDU)
	pduBytes[0] = 0xA2 // GET-RESPONSE
	respMsg := SNMPMessage{Version: msg.Version, Community: msg.Community, Data: asn1.RawValue{FullBytes: pduBytes}}
	respBytes, _ := asn1.Marshal(respMsg)
	conn.WriteToUDP(respBytes, addr)
	fmt.Printf("[+] Responded to %X for %d bindings\n", originalTag, len(responseBindings))
}
