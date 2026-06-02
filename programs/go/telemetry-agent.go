package main

// Author: David Vanhoucke <dvanhoucke@redborder.com>

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"
)

const VERSION = "v1.11 (2026-06-02)"

type NetFlowV5Header struct {
	Version uint16; Count uint16; SysUptime uint32; UnixSecs uint32; UnixNanos uint32; FlowSequence uint32; EngineType uint8; EngineID uint8; SamplingInterval uint16
}

type NetFlowV5Record struct {
	SrcAddr [4]byte; DstAddr [4]byte; NextHop [4]byte; Input uint16; Output uint16; DPkts uint32; DOctets uint32; First uint32; Last uint32; SrcPort uint16; DstPort uint16; Pad1 uint8; TCPFlags uint8; Prot uint8; Tos uint8; SrcAs uint16; DstAs uint16; SrcMask uint8; DstMask uint8; Pad2 uint16
}

type NetFlowV9Header struct {
	Version uint16; Count uint16; SysUptime uint32; UnixSecs uint32; FlowSequence uint32; SourceID uint32
}

type NetFlowV9Field struct {
	Type uint16; Length uint16
}

type IPFIXHeader struct {
	Version uint16; Length uint16; ExportTime uint32; SequenceNumber uint32; DomainID uint32
}

type Config struct {
	Mode string `json:"mode"`; Target string `json:"target"`; Port int `json:"port"`; Rate int `json:"rate"`; RateModel string `json:"rate_model"`; Records int `json:"records"`; EngineType uint8 `json:"engine_type"`; EngineID uint8 `json:"engine_id"`; SourceID uint32 `json:"source_id"`; SamplingRate uint32 `json:"sampling_rate"`; Scenarios []FlowScenario `json:"scenarios"`; PcapFile string `json:"pcap_file"`
}

type PcapPacket struct {
	SrcIP, DstIP net.IP; SrcPort, DstPort uint16; Proto uint8; Length uint32; Header []byte
}

func getLocalIP() net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil { return net.IPv4(127, 0, 0, 1) }
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ip4 := ipnet.IP.To4(); ip4 != nil { return ip4 }
		}
	}
	return net.IPv4(127, 0, 0, 1)
}

func getLocalMAC() net.HardwareAddr {
	ifaces, err := net.Interfaces()
	if err != nil { return net.HardwareAddr{0, 0, 0, 0, 0, 0} }
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback == 0 && iface.HardwareAddr != nil { return iface.HardwareAddr }
	}
	return net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
}

func readPcap(filename string) ([]PcapPacket, error) {
	f, err := os.Open(filename); if err != nil { return nil, err }
	defer f.Close()

	header := make([]byte, 24); if _, err := f.Read(header); err != nil { return nil, err }
	var isLittle bool
	var linkType uint32

	if bytes.Equal(header[0:4], []byte{0xd4, 0xc3, 0xb2, 0xa1}) {
		isLittle = true
		linkType = binary.LittleEndian.Uint32(header[20:24])
	} else if bytes.Equal(header[0:4], []byte{0xa1, 0xb2, 0xc3, 0xd4}) {
		isLittle = false
		linkType = binary.BigEndian.Uint32(header[20:24])
	} else if bytes.Equal(header[0:4], []byte{0x0a, 0x0d, 0x0d, 0x0a}) {
		return nil, fmt.Errorf("PCAPNG format not supported yet (use 'tcpdump -r file.pcapng -w file.pcap' to convert)")
	} else {
		return nil, fmt.Errorf("invalid pcap magic: %02x%02x%02x%02x", header[0], header[1], header[2], header[3])
	}

	fmt.Printf("[*] PCAP LinkType: %d\n", linkType)
	var packets []PcapPacket
	totalRead := 0
	for {
		ph := make([]byte, 16); if _, err := f.Read(ph); err != nil { break }
		totalRead++
		var inclLen uint32
		if isLittle { inclLen = binary.LittleEndian.Uint32(ph[8:12]) } else { inclLen = binary.BigEndian.Uint32(ph[8:12]) }
		data := make([]byte, inclLen); if _, err := f.Read(data); err != nil { break }

		var ethType uint16
		var ipStart int

		switch linkType {
		case 1: // Ethernet
			if len(data) < 14 { continue }
			ethType = binary.BigEndian.Uint16(data[12:14])
			ipStart = 14
		case 113: // Linux Cooked (SLL)
			if len(data) < 16 { continue }
			ethType = binary.BigEndian.Uint16(data[14:16])
			ipStart = 16
		case 276: // Linux Cooked v2 (SLL2)
			if len(data) < 20 { continue }
			ethType = binary.BigEndian.Uint16(data[0:2])
			ipStart = 20
		default:
			if totalRead == 1 { fmt.Printf("[-] Unsupported PCAP LinkType: %d\n", linkType) }
			continue
		}

		if ethType != 0x0800 { continue } // Only IPv4 for now
		ip := data[ipStart:]
		if len(ip) < 20 { continue }
		proto := ip[9]; srcIP := net.IP(ip[12:16]); dstIP := net.IP(ip[16:20])
		ihL := int(ip[0]&0x0f) * 4; transport := ip[ihL:]
		var sp, dp uint16
		if (proto == 6 || proto == 17) && len(transport) >= 4 {
			sp = binary.BigEndian.Uint16(transport[0:2]); dp = binary.BigEndian.Uint16(transport[2:4])
		}
		packets = append(packets, PcapPacket{SrcIP: srcIP, DstIP: dstIP, SrcPort: sp, DstPort: dp, Proto: proto, Length: uint32(len(data)), Header: data})
	}
	if totalRead > 0 && len(packets) == 0 {
		fmt.Printf("[!] Warning: Read %d packets from PCAP but 0 matched (not IPv4 or unsupported link type)\n", totalRead)
	}
	return packets, nil
}

type FlowScenario struct {
	Name string `json:"name"`; SrcCIDR string `json:"src_cidr"`; DstCIDR string `json:"dst_cidr"`; SrcPorts []uint16 `json:"src_ports"`; DstPorts []uint16 `json:"dst_ports"`; Protos []uint8 `json:"protos"`; Weight int `json:"weight"`; Events []string `json:"events"`
	MinPkts int `json:"min_pkts"`; MaxPkts int `json:"max_pkts"`; MinBytes int `json:"min_bytes"`; MaxBytes int `json:"max_bytes"`
}

func (s *FlowScenario) GetRandomFlow(rng *rand.Rand) (net.IP, net.IP, uint16, uint16, uint8) {
	var sp, dp uint16
	var pr uint8 = 6
	if len(s.SrcPorts) > 0 { sp = s.SrcPorts[rng.Intn(len(s.SrcPorts))] } else { sp = uint16(rng.Intn(64511) + 1024) }
	if len(s.DstPorts) > 0 { dp = s.DstPorts[rng.Intn(len(s.DstPorts))] } else { dp = uint16(rng.Intn(64511) + 1024) }
	if len(s.Protos) > 0 { pr = s.Protos[rng.Intn(len(s.Protos))] }
	return getRandomIP(s.SrcCIDR, rng), getRandomIP(s.DstCIDR, rng), sp, dp, pr
}

func (s *FlowScenario) GetRandomVolume(rng *rand.Rand) (uint32, uint32) {
	pkts := uint32(rng.Intn(100) + 1)
	if s.MaxPkts > 0 && s.MaxPkts >= s.MinPkts { pkts = uint32(rng.Intn(s.MaxPkts-s.MinPkts+1) + s.MinPkts) }
	bytes := pkts * uint32(rng.Intn(1000)+64)
	if s.MaxBytes > 0 && s.MaxBytes >= s.MinBytes { bytes = uint32(rng.Intn(s.MaxBytes-s.MinBytes+1) + s.MinBytes) }
	return pkts, bytes
}

func getRandomIP(cidr string, rng *rand.Rand) net.IP {
	if cidr == "" { return net.IPv4(uint8(rng.Intn(254)+1), uint8(rng.Intn(254)), uint8(rng.Intn(254)), uint8(rng.Intn(254))) }
	_, ipnet, err := net.ParseCIDR(cidr); if err != nil { return net.ParseIP("127.0.0.1") }
	ip := make(net.IP, len(ipnet.IP)); copy(ip, ipnet.IP)
	for i := range ipnet.Mask { if ipnet.Mask[i] != 255 { ip[i] = (ip[i] & ipnet.Mask[i]) | (uint8(rng.Intn(256)) & ^ipnet.Mask[i]) } }
	return ip
}

func hexDump(data []byte) {
	fmt.Printf(" [HEX] "); for i, b := range data { fmt.Printf("%02x ", b); if (i+1)%16 == 0 && i+1 < len(data) { fmt.Printf("\n [HEX] ") } }
	fmt.Printf("\n")
}

func pickScenario(scenarios []FlowScenario, rng *rand.Rand) *FlowScenario {
	if len(scenarios) == 0 {
		return &FlowScenario{Name: "fallback", Weight: 100}
	}
	total := 0; for _, s := range scenarios { total += s.Weight }
	if total == 0 { return &scenarios[0] }
	r := rng.Intn(total); for _, s := range scenarios { r -= s.Weight; if r < 0 { return &s } }
	return &scenarios[0]
}

func getNextDelay(rate int, model string, rng *rand.Rand) time.Duration {
	if rate <= 0 { return time.Second }
	base := time.Second / time.Duration(rate)
	switch model {
	case "jitter":
		variation := time.Duration(rng.Intn(int(base/2))) - (base / 4)
		return base + variation
	case "poisson":
		return time.Duration(rng.ExpFloat64() * float64(base))
	case "bursty":
		if rng.Intn(100) < 90 { return base * 5 } // 90% quiet
		return base / 10 // 10% burst
	default:
		return base
	}
}

func runNetFlowV5(addr string, cfg Config, debug bool) {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil { fmt.Printf("[-] Error resolving address: %v\n", err); return }
	var conn *net.UDPConn
	boot := time.Now().Add(-100 * time.Second); var flowSeq uint32 = 0; rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var pcapPkts []PcapPacket; pcapIdx := 0; localIP := getLocalIP()
	if cfg.PcapFile != "" {
		pcapPkts, err = readPcap(cfg.PcapFile)
		if err != nil { fmt.Printf("[-] Error reading PCAP: %v\n", err); os.Exit(1) }
		if len(pcapPkts) == 0 { fmt.Printf("[-] PCAP file contains no usable packets. Exiting.\n"); os.Exit(1) }
		fmt.Printf("[+] Loaded %d packets from PCAP\n", len(pcapPkts))
	}

	for {
		if conn == nil {
			conn, err = net.DialUDP("udp", nil, raddr)
			if err != nil {
				fmt.Printf("[-] Error connecting: %v\n", err)
				time.Sleep(time.Second)
				continue
			}
			localIP = getLocalIP()
		}
		buf := new(bytes.Buffer); now := time.Now(); uptime := uint32(time.Since(boot).Milliseconds())
		binary.Write(buf, binary.BigEndian, NetFlowV5Header{Version: 5, Count: uint16(cfg.Records), SysUptime: uptime, UnixSecs: uint32(now.Unix()), UnixNanos: uint32(now.UnixNano() % 1000000000), FlowSequence: flowSeq, EngineType: cfg.EngineType, EngineID: cfg.EngineID})
		flowSeq += uint32(cfg.Records)
		for i := 0; i < cfg.Records; i++ {
			var src, dst net.IP; var sp, dp uint16; var pr uint8; var pkts, octets uint32
			if len(pcapPkts) > 0 {
				p := pcapPkts[pcapIdx]; pcapIdx = (pcapIdx + 1) % len(pcapPkts)
				src, dst, sp, dp, pr, pkts, octets = localIP, p.DstIP, p.SrcPort, p.DstPort, p.Proto, 1, p.Length
			} else {
				s := pickScenario(cfg.Scenarios, rng); src, dst, sp, dp, pr = s.GetRandomFlow(rng); pkts, octets = s.GetRandomVolume(rng)
			}
			dur := uint32(rng.Intn(5000) + 100)
			r := NetFlowV5Record{Input: 1, Output: 2, DPkts: pkts, DOctets: octets, First: uptime - dur, Last: uptime, SrcPort: sp, DstPort: dp, Prot: pr, TCPFlags: 0x10, SrcMask: 24, DstMask: 24}
			copy(r.SrcAddr[:], src.To4()); copy(r.DstAddr[:], dst.To4())
			binary.Write(buf, binary.BigEndian, r)
		}
		data := buf.Bytes(); if debug { hexDump(data) }; _, err := conn.Write(data)
		if err != nil {
			fmt.Printf("[-] Error sending V5: %v\n", err)
			conn.Close(); conn = nil
		} else {
			fmt.Printf("[+] Sent V5 (%d records)\n", cfg.Records)
		}
		time.Sleep(getNextDelay(cfg.Rate, cfg.RateModel, rng))
	}
}

func runNetFlowV9(addr string, cfg Config, debug bool) {
	var conn net.Conn
	var err error
	boot := time.Now().Add(-100 * time.Second)
	var seq uint32 = 0; rng := rand.New(rand.NewSource(time.Now().UnixNano())); lastTmpl := time.Now().Add(-1 * time.Hour)
	fields := []NetFlowV9Field{{8, 4}, {12, 4}, {7, 2}, {11, 2}, {4, 1}, {1, 4}, {2, 4}}
	var pcapPkts []PcapPacket; pcapIdx := 0; localIP := getLocalIP()
	if cfg.PcapFile != "" {
		pcapPkts, err = readPcap(cfg.PcapFile)
		if err != nil { fmt.Printf("[-] Error reading PCAP: %v\n", err); os.Exit(1) }
		if len(pcapPkts) == 0 { fmt.Printf("[-] PCAP file contains no usable packets. Exiting.\n"); os.Exit(1) }
		fmt.Printf("[+] Loaded %d packets from PCAP\n", len(pcapPkts))
	}

	sendV9Tmpl := func() {
		if conn == nil { return }
		buf := new(bytes.Buffer); uptime := uint32(time.Since(boot).Milliseconds())
		binary.Write(buf, binary.BigEndian, NetFlowV9Header{Version: 9, Count: 1, SysUptime: uptime, UnixSecs: uint32(time.Now().Unix()), FlowSequence: seq, SourceID: cfg.SourceID})
		seq++; binary.Write(buf, binary.BigEndian, uint16(0)); binary.Write(buf, binary.BigEndian, uint16(4+4+(len(fields)*4)))
		binary.Write(buf, binary.BigEndian, uint16(257)); binary.Write(buf, binary.BigEndian, uint16(len(fields)))
		for _, f := range fields { binary.Write(buf, binary.BigEndian, f) }
		data := buf.Bytes(); if debug { hexDump(data) }; _, err := conn.Write(data)
		if err != nil {
			fmt.Printf("[-] Error sending V9 Template: %v\n", err)
			conn.Close(); conn = nil
		} else {
			fmt.Println("[+] Sent V9 Template")
			lastTmpl = time.Now()
		}
	}
	for {
		if conn == nil {
			conn, err = net.Dial("udp", addr)
			if err != nil {
				fmt.Printf("[-] Error connecting: %v\n", err)
				time.Sleep(time.Second)
				continue
			}
			localIP = getLocalIP()
			lastTmpl = time.Now().Add(-1 * time.Hour) // Force template resend on reconnect
		}
		if time.Since(lastTmpl) > 30*time.Second { sendV9Tmpl() }
		if conn == nil { continue } // sendV9Tmpl might have failed and set conn to nil

		buf := new(bytes.Buffer); uptime := uint32(time.Since(boot).Milliseconds())
		binary.Write(buf, binary.BigEndian, NetFlowV9Header{Version: 9, Count: 1, SysUptime: uptime, UnixSecs: uint32(time.Now().Unix()), FlowSequence: seq, SourceID: cfg.SourceID})
		seq++; binary.Write(buf, binary.BigEndian, uint16(257)); binary.Write(buf, binary.BigEndian, uint16(4+(cfg.Records*21)))
		for i := 0; i < cfg.Records; i++ {
			var src, dst net.IP; var sp, dp uint16; var pr uint8; var pkts, octets uint32
			if len(pcapPkts) > 0 {
				p := pcapPkts[pcapIdx]; pcapIdx = (pcapIdx + 1) % len(pcapPkts)
				src, dst, sp, dp, pr, pkts, octets = localIP, p.DstIP, p.SrcPort, p.DstPort, p.Proto, 1, p.Length
			} else {
				s := pickScenario(cfg.Scenarios, rng); src, dst, sp, dp, pr = s.GetRandomFlow(rng); pkts, octets = s.GetRandomVolume(rng)
			}
			binary.Write(buf, binary.BigEndian, src.To4()); binary.Write(buf, binary.BigEndian, dst.To4()); binary.Write(buf, binary.BigEndian, sp); binary.Write(buf, binary.BigEndian, dp); binary.Write(buf, binary.BigEndian, pr); binary.Write(buf, binary.BigEndian, octets); binary.Write(buf, binary.BigEndian, pkts)
		}
		for buf.Len()%4 != 0 { buf.WriteByte(0) }
		data := buf.Bytes(); if debug { hexDump(data) }; _, err := conn.Write(data)
		if err != nil {
			fmt.Printf("[-] Error sending V9: %v\n", err)
			conn.Close(); conn = nil
		} else {
			fmt.Printf("[+] Sent V9 (%d records)\n", cfg.Records)
		}
		time.Sleep(getNextDelay(cfg.Rate, cfg.RateModel, rng))
	}
}

func runSyslog(addr string, cfg Config) {
	var conn net.Conn
	var err error
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var pcapPkts []PcapPacket; pcapIdx := 0
	if cfg.PcapFile != "" {
		pcapPkts, err = readPcap(cfg.PcapFile)
		if err != nil { fmt.Printf("[-] Error reading PCAP: %v\n", err); os.Exit(1) }
		if len(pcapPkts) == 0 { fmt.Printf("[-] PCAP file contains no usable packets. Exiting.\n"); os.Exit(1) }
		fmt.Printf("[+] Loaded %d packets from PCAP\n", len(pcapPkts))
	}

	for {
		if conn == nil {
			conn, err = net.Dial("udp", addr)
			if err != nil {
				fmt.Printf("[-] Error connecting: %v\n", err)
				time.Sleep(time.Second)
				continue
			}
		}
		var event string; var sName string
		if len(pcapPkts) > 0 {
			p := pcapPkts[pcapIdx]; pcapIdx = (pcapIdx + 1) % len(pcapPkts)
			event = fmt.Sprintf("PCAP: %s:%d -> %s:%d (proto %d, len %d)", p.SrcIP, p.SrcPort, p.DstIP, p.DstPort, p.Proto, p.Length); sName = "pcap"
		} else {
			s := pickScenario(cfg.Scenarios, rng); _, _, _, _, _ = s.GetRandomFlow(rng)
			if len(s.Events) > 0 { event = s.Events[rng.Intn(len(s.Events))] } else { event = fmt.Sprintf("TRAFFIC: %s observed", s.Name) }; sName = s.Name
		}
		msg := fmt.Sprintf("<134>1 %s sensor-sandbox security-engine %d MSG-01 - %s\n", time.Now().Format(time.RFC3339Nano), os.Getpid(), event)
		_, err := conn.Write([]byte(msg))
		if err != nil {
			fmt.Printf("[-] Error sending Syslog: %v\n", err)
			conn.Close(); conn = nil
		} else {
			fmt.Printf("[+] Sent Syslog: %s\n", sName)
		}
		time.Sleep(getNextDelay(cfg.Rate, cfg.RateModel, rng))
	}
}

func runIPFIX(addr string, cfg Config, debug bool) {
	var conn net.Conn
	var err error
	var seq uint32 = 0; rng := rand.New(rand.NewSource(time.Now().UnixNano())); lastTmpl := time.Now().Add(-1 * time.Hour)
	fields := []NetFlowV9Field{{8, 4}, {12, 4}, {7, 2}, {11, 2}, {4, 1}, {1, 4}, {2, 4}}
	var pcapPkts []PcapPacket; pcapIdx := 0; localIP := getLocalIP()
	if cfg.PcapFile != "" {
		pcapPkts, err = readPcap(cfg.PcapFile)
		if err != nil { fmt.Printf("[-] Error reading PCAP: %v\n", err); os.Exit(1) }
		if len(pcapPkts) == 0 { fmt.Printf("[-] PCAP file contains no usable packets. Exiting.\n"); os.Exit(1) }
		fmt.Printf("[+] Loaded %d packets from PCAP\n", len(pcapPkts))
	}

	sendIPFIXTmpl := func() {
		if conn == nil { return }
		buf := new(bytes.Buffer); buf.Write(make([]byte, 16))
		binary.Write(buf, binary.BigEndian, uint16(2)); binary.Write(buf, binary.BigEndian, uint16(4+4+(len(fields)*4)))
		binary.Write(buf, binary.BigEndian, uint16(258)); binary.Write(buf, binary.BigEndian, uint16(len(fields)))
		for _, f := range fields { binary.Write(buf, binary.BigEndian, f) }
		data := buf.Bytes(); binary.BigEndian.PutUint16(data[0:2], 10); binary.BigEndian.PutUint16(data[2:4], uint16(len(data))); binary.BigEndian.PutUint32(data[4:8], uint32(time.Now().Unix())); binary.BigEndian.PutUint32(data[8:12], seq); binary.BigEndian.PutUint32(data[12:16], cfg.SourceID)
		seq++; if debug { hexDump(data) }; _, err := conn.Write(data)
		if err != nil {
			fmt.Printf("[-] Error sending IPFIX Template: %v\n", err)
			conn.Close(); conn = nil
		} else {
			fmt.Println("[+] Sent IPFIX Template")
			lastTmpl = time.Now()
		}
	}
	for {
		if conn == nil {
			conn, err = net.Dial("udp", addr)
			if err != nil {
				fmt.Printf("[-] Error connecting: %v\n", err)
				time.Sleep(time.Second)
				continue
			}
			localIP = getLocalIP()
			lastTmpl = time.Now().Add(-1 * time.Hour)
		}
		if time.Since(lastTmpl) > 30*time.Second { sendIPFIXTmpl() }
		if conn == nil { continue }

		buf := new(bytes.Buffer); buf.Write(make([]byte, 16))
		binary.Write(buf, binary.BigEndian, uint16(258)); binary.Write(buf, binary.BigEndian, uint16(4+(cfg.Records*21)))
		for i := 0; i < cfg.Records; i++ {
			var src, dst net.IP; var sp, dp uint16; var pr uint8; var pkts, octets uint32
			if len(pcapPkts) > 0 {
				p := pcapPkts[pcapIdx]; pcapIdx = (pcapIdx + 1) % len(pcapPkts)
				src, dst, sp, dp, pr, pkts, octets = localIP, p.DstIP, p.SrcPort, p.DstPort, p.Proto, 1, p.Length
			} else {
				s := pickScenario(cfg.Scenarios, rng); src, dst, sp, dp, pr = s.GetRandomFlow(rng); pkts, octets = s.GetRandomVolume(rng)
			}
			binary.Write(buf, binary.BigEndian, src.To4()); binary.Write(buf, binary.BigEndian, dst.To4()); binary.Write(buf, binary.BigEndian, sp); binary.Write(buf, binary.BigEndian, dp); binary.Write(buf, binary.BigEndian, pr); binary.Write(buf, binary.BigEndian, octets); binary.Write(buf, binary.BigEndian, pkts)
		}
		data := buf.Bytes(); binary.BigEndian.PutUint16(data[0:2], 10); binary.BigEndian.PutUint16(data[2:4], uint16(len(data))); binary.BigEndian.PutUint32(data[4:8], uint32(time.Now().Unix())); binary.BigEndian.PutUint32(data[8:12], seq); binary.BigEndian.PutUint32(data[12:16], cfg.SourceID)
		seq++; data2 := buf.Bytes(); if debug { hexDump(data2) }; _, err := conn.Write(data2)
		if err != nil {
			fmt.Printf("[-] Error sending IPFIX: %v\n", err)
			conn.Close(); conn = nil
		} else {
			fmt.Printf("[+] Sent IPFIX (%d records)\n", cfg.Records)
		}
		time.Sleep(getNextDelay(cfg.Rate, cfg.RateModel, rng))
	}
}

func runSFlow(addr string, cfg Config, debug bool) {
	var conn net.Conn
	var err error
	boot := time.Now().Add(-100 * time.Second); var dgSeq, sampleSeq uint32 = 0, 0; rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	if cfg.SamplingRate == 0 { cfg.SamplingRate = 100 }

	var agentIP []byte
	var pcapPkts []PcapPacket; pcapIdx := 0; localIP := getLocalIP(); localMAC := getLocalMAC()
	if cfg.PcapFile != "" {
		pcapPkts, err = readPcap(cfg.PcapFile)
		if err != nil { fmt.Printf("[-] Error reading PCAP: %v\n", err); os.Exit(1) }
		if len(pcapPkts) == 0 { fmt.Printf("[-] PCAP file contains no usable packets. Exiting.\n"); os.Exit(1) }
		fmt.Printf("[+] Loaded %d packets from PCAP\n", len(pcapPkts))
	}

	for {
		if conn == nil {
			conn, err = net.Dial("udp", addr)
			if err != nil {
				fmt.Printf("[-] Error connecting: %v\n", err)
				time.Sleep(time.Second)
				continue
			}
			// Determine local IP for Agent IP field
			localAddr := conn.LocalAddr().(*net.UDPAddr)
			agentIP = localAddr.IP.To4()
			if agentIP == nil { agentIP = net.ParseIP("0.0.0.0").To4() }
			localIP = getLocalIP(); localMAC = getLocalMAC()
		}

		buf := new(bytes.Buffer); uptime := uint32(time.Since(boot).Milliseconds())
		binary.Write(buf, binary.BigEndian, uint32(5))     // sFlow Version
		binary.Write(buf, binary.BigEndian, uint32(1))     // IP Version (IPv4)
		binary.Write(buf, binary.BigEndian, [4]byte{agentIP[0], agentIP[1], agentIP[2], agentIP[3]}) // Agent IP
		binary.Write(buf, binary.BigEndian, uint32(0))     // Sub-agent ID
		binary.Write(buf, binary.BigEndian, dgSeq)
		binary.Write(buf, binary.BigEndian, uptime)
		binary.Write(buf, binary.BigEndian, uint32(cfg.Records)) // Num Samples
		dgSeq++

		for i := 0; i < cfg.Records; i++ {
			var src, dst net.IP; var sp, dp uint16; var pr uint8; var octets uint32; var headerBytes []byte
			if len(pcapPkts) > 0 {
				p := pcapPkts[pcapIdx]; pcapIdx = (pcapIdx + 1) % len(pcapPkts)
				src, dst, sp, dp, pr, octets = localIP, p.DstIP, p.SrcPort, p.DstPort, p.Proto, p.Length
				headerBytes = make([]byte, len(p.Header)); copy(headerBytes, p.Header)
				// Spoof Source IP and MAC in the header sample
				if len(headerBytes) >= 34 {
					copy(headerBytes[6:12], localMAC) // Src MAC
					copy(headerBytes[26:30], localIP.To4()) // Src IP
				}
			} else {
				s := pickScenario(cfg.Scenarios, rng); src, dst, sp, dp, pr = s.GetRandomFlow(rng)
				_, octets = s.GetRandomVolume(rng)
				// Mock Ethernet + IP Header
				hBuf := new(bytes.Buffer)
				hBuf.Write([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) // Dest MAC
				hBuf.Write(localMAC) // Src MAC
				hBuf.Write([]byte{0x08, 0x00}) // Type IPv4
				hBuf.Write([]byte{0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, pr, 0x00, 0x00}) // IP Header start
				hBuf.Write(src.To4()); hBuf.Write(dst.To4())
				binary.Write(hBuf, binary.BigEndian, sp); binary.Write(hBuf, binary.BigEndian, dp)
				headerBytes = hBuf.Bytes()
			}

			sampleBuf := new(bytes.Buffer)
			binary.Write(sampleBuf, binary.BigEndian, sampleSeq); sampleSeq++
			binary.Write(sampleBuf, binary.BigEndian, uint32(1)) // SourceID (ifIndex 1)
			binary.Write(sampleBuf, binary.BigEndian, cfg.SamplingRate)
			binary.Write(sampleBuf, binary.BigEndian, sampleSeq * cfg.SamplingRate) // Sample Pool
			binary.Write(sampleBuf, binary.BigEndian, uint32(0)) // Drops
			binary.Write(sampleBuf, binary.BigEndian, uint32(1)) // Input If
			binary.Write(sampleBuf, binary.BigEndian, uint32(2)) // Output If
			binary.Write(sampleBuf, binary.BigEndian, uint32(1)) // Num Records

			// Flow Record: Sampled Header (Enterprise 0, Format 1)
			recordBuf := new(bytes.Buffer)
			binary.Write(recordBuf, binary.BigEndian, uint32(1)) // Header Protocol (Ethernet)
			binary.Write(recordBuf, binary.BigEndian, uint32(octets)) // Frame Length
			binary.Write(recordBuf, binary.BigEndian, uint32(0)) // Payout (stripped)

			binary.Write(recordBuf, binary.BigEndian, uint32(len(headerBytes)))
			recordBuf.Write(headerBytes)
			for recordBuf.Len()%4 != 0 { recordBuf.WriteByte(0) } // Padding

			// Write Flow Record Header (Enterprise 0, Format 1)
			binary.Write(sampleBuf, binary.BigEndian, uint32(1)) // Format 1
			binary.Write(sampleBuf, binary.BigEndian, uint32(recordBuf.Len()))
			sampleBuf.Write(recordBuf.Bytes())

			// Write Sample Header (Enterprise 0, Format 1 = Flow Sample)
			binary.Write(buf, binary.BigEndian, uint32(1)) // Format 1
			binary.Write(buf, binary.BigEndian, uint32(sampleBuf.Len()))
			buf.Write(sampleBuf.Bytes())
		}

		data := buf.Bytes(); if debug { hexDump(data) }; _, err := conn.Write(data)
		if err != nil {
			fmt.Printf("[-] Error sending sFlow: %v\n", err)
			conn.Close(); conn = nil
		} else {
			fmt.Printf("[+] Sent sFlow (%d samples)\n", cfg.Records)
		}
		time.Sleep(getNextDelay(cfg.Rate, cfg.RateModel, rng))
	}
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "[+] Redborder Telemetry Agent %s\n", VERSION)
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nRate Models (-model):\n")
		fmt.Fprintf(os.Stderr, "  fixed   - Constant rate (default)\n")
		fmt.Fprintf(os.Stderr, "  jitter  - Random +/- 25%% variation around target rate\n")
		fmt.Fprintf(os.Stderr, "  poisson - Exponentially distributed intervals (Poisson arrival process)\n")
		fmt.Fprintf(os.Stderr, "  bursty  - Mostly quiet, with occasional high-volume bursts\n")
	}
	cP := flag.String("config", "", "JSON config file"); modeF := flag.String("mode", "netflow5", "netflow5|netflow9|syslog|ipfix|sflow"); targetF := flag.String("target", "127.0.0.1", "Target IP"); portF := flag.Int("port", 2055, "Target Port"); rateF := flag.Int("rate", 5, "Records per second"); modelF := flag.String("model", "fixed", "fixed|jitter|poisson|bursty"); recordsF := flag.Int("records", 10, "Records per packet"); samplingF := flag.Int("sampling", 100, "sFlow sampling rate (1-in-N)"); debugF := flag.Bool("debug", false, "Enable debug mode"); pcapF := flag.String("pcap", "", "PCAP file to replay"); flag.Parse()
	fmt.Printf("[+] Redborder Telemetry Agent %s\n", VERSION)

	// Default configuration
	cfg := Config{Mode: *modeF, Target: *targetF, Port: *portF, Rate: *rateF, RateModel: *modelF, Records: *recordsF, EngineType: 1, EngineID: 1, SourceID: 1001, SamplingRate: uint32(*samplingF), Scenarios: []FlowScenario{{Name: "default", SrcCIDR: "10.0.0.0/8", DstCIDR: "192.168.0.0/16", SrcPorts: []uint16{1024}, DstPorts: []uint16{80}, Protos: []uint8{6}, Weight: 100}}, PcapFile: *pcapF}

	// Overwrite with config file if provided
	if *cP != "" {
		f, err := os.ReadFile(*cP); if err != nil { fmt.Printf("[-] Error reading config: %v\n", err); os.Exit(1) }
		if err := json.Unmarshal(f, &cfg); err != nil { fmt.Printf("[-] Error parsing config: %v\n", err); os.Exit(1) }
	}

	// Finally, overwrite with explicit command-line flags (highest priority)
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "mode": cfg.Mode = *modeF
		case "target": cfg.Target = *targetF
		case "port": cfg.Port = *portF
		case "rate": cfg.Rate = *rateF
		case "model": cfg.RateModel = *modelF
		case "records": cfg.Records = *recordsF
		case "sampling": cfg.SamplingRate = uint32(*samplingF)
		case "pcap": cfg.PcapFile = *pcapF
		}
	})

	if cfg.Target == "127.0.0.1" || cfg.Target == "localhost" { fmt.Println("[!] WARNING: Target is 127.0.0.1. Packets may not leave the sandbox!") }
	addr := fmt.Sprintf("%s:%d", cfg.Target, cfg.Port); fmt.Printf("[+] Mode: %s | Target: %s | Rate: %d (%s) | Records: %d | Debug: %v\n", cfg.Mode, addr, cfg.Rate, cfg.RateModel, cfg.Records, *debugF)
	switch cfg.Mode {
	case "netflow5": runNetFlowV5(addr, cfg, *debugF)
	case "netflow9": runNetFlowV9(addr, cfg, *debugF)
	case "syslog": runSyslog(addr, cfg)
	case "ipfix": runIPFIX(addr, cfg, *debugF)
	case "sflow":
		if cfg.Port == 2055 { cfg.Port = 6343; addr = fmt.Sprintf("%s:%d", cfg.Target, cfg.Port); fmt.Printf("[!] Switching to default sFlow port: %d\n", cfg.Port) }
		runSFlow(addr, cfg, *debugF)
	default: fmt.Println("[-] Unknown mode"); os.Exit(1)
	}
}
