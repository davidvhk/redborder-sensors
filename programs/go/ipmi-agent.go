package main

// Author: David Vanhoucke <dvanhoucke@redborder.com>

import (
	"crypto/md5"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
)

type Config struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

var (
	config     Config
	seqCounter uint32 = 1
	sdrRepo    [][]byte
)

func createFullSensorRecord(recID uint16, sensorNum byte, name string, unit byte) []byte {
	nameBytes := []byte(name)
	recLen := byte(43 + len(nameBytes))
	rec := []byte{byte(recID), byte(recID >> 8), 0x51, 0x01, recLen}
	payload := make([]byte, 43)
	payload[0], payload[2], payload[3], payload[4], payload[5], payload[6], payload[8], payload[15], payload[16], payload[19], payload[42] = 0x20, sensorNum, 0x04, 0x01, 0x7f, 0x68, 0x01, 0x80, unit, 0x01, 0xc0|byte(len(nameBytes))
	payload[7] = 0x01
	if unit == 0x12 { payload[7] = 0x04 }
	return append(append(rec, payload...), nameBytes...)
}

func initSDR() {
	sdrRepo = [][]byte{
		createFullSensorRecord(1, 1, "System Temp", 0x01),
		createFullSensorRecord(2, 2, "PCH Temp", 0x01),
		createFullSensorRecord(3, 3, "Peripheral Temp", 0x01),
		createFullSensorRecord(4, 4, "Fan Speed", 0x12),
	}
}

func main() {
	configPath := flag.String("config", "", "Path to config")
	listenAddr := flag.String("listen", ":623", "Listen address")
	flag.Parse()
	fmt.Printf("[!] IPMI Mock Agent v1.45 starting (STRICT FALLBACK)...\n")
	if *configPath != "" {
		data, _ := os.ReadFile(*configPath)
		json.Unmarshal(data, &config)
	}
	initSDR()
	addr, _ := net.ResolveUDPAddr("udp", *listenAddr)
	conn, _ := net.ListenUDP("udp", addr)
	defer conn.Close()
	fmt.Printf("[+] IPMI Mock Agent (v1.45) listening on %s\n", *listenAddr)
	buf := make([]byte, 2048)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err == nil { handlePacket(conn, remoteAddr, buf[:n]) }
	}
}

func handlePacket(conn *net.UDPConn, addr *net.UDPAddr, data []byte) {
	if len(data) < 4 || data[0] != 0x06 || data[3] != 0x07 { return }
	authType, sessionID, ipmiOffset := data[4], data[9:13], 14
	if authType != 0 { ipmiOffset = 30 }
	if len(data) >= ipmiOffset+6 {
		rmcpSeq, ipmiMsg := data[2], data[ipmiOffset:]
		netFn, lun, sourceAddr, reqSeq, cmd := ipmiMsg[1]>>2, ipmiMsg[1]&0x03, ipmiMsg[3], ipmiMsg[4], ipmiMsg[5]
		fmt.Printf("[*] [%s] NetFn: 0x%02x, Cmd: 0x%02x\n", addr, netFn, cmd)

		switch {
		case netFn == 0x06 && cmd == 0x38:
			sendResponse(conn, addr, rmcpSeq, authType, sessionID, sourceAddr, reqSeq, 0x06, lun, cmd, []byte{0x00, 0x01, 0x05, 0x02, 0x00, 0x00, 0x00, 0x00})
		case netFn == 0x06 && cmd == 0x39:
			sendResponse(conn, addr, rmcpSeq, authType, sessionID, sourceAddr, reqSeq, 0x06, lun, cmd, append([]byte{0x00, 0x11, 0x22, 0x33, 0x44}, make([]byte, 16)...))
		case netFn == 0x06 && cmd == 0x3a:
			sendResponse(conn, addr, rmcpSeq, authType, sessionID, sourceAddr, reqSeq, 0x06, lun, cmd, []byte{0x00, authType, 0x11, 0x22, 0x33, 0x44, 0x01, 0x00, 0x00, 0x00, 0x04})
		case netFn == 0x06 && cmd == 0x3b:
			sendResponse(conn, addr, rmcpSeq, authType, sessionID, sourceAddr, reqSeq, 0x06, lun, cmd, []byte{0x00, 0x04})
		case netFn == 0x06 && cmd == 0x3e: // Get Session GUID (Standard)
			guid := []byte{0xde, 0xad, 0xbe, 0xef, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xaa, 0xbb}
			sendResponse(conn, addr, rmcpSeq, authType, sessionID, sourceAddr, reqSeq, 0x06, lun, cmd, append([]byte{0x00}, guid...))
		case netFn == 0x2c && cmd == 0x3e: // Reject DCMI GUID to force fallback
			sendResponse(conn, addr, rmcpSeq, authType, sessionID, sourceAddr, reqSeq, 0x2c, lun, cmd, []byte{0xc1})
		case netFn == 0x06 && cmd == 0x01:
			sendResponse(conn, addr, rmcpSeq, authType, sessionID, sourceAddr, reqSeq, 0x06, lun, cmd, []byte{0x00, 0x01, 0x81, 0x01, 0x01, 0x02, 0xbf, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		case netFn == 0x2c && cmd == 0x00:
			sendResponse(conn, addr, rmcpSeq, authType, sessionID, sourceAddr, reqSeq, 0x2c, lun, cmd, []byte{0x00, 0xdc, 0x01, 0x00})
		case netFn == 0x0a && cmd == 0x20:
			c := uint16(len(sdrRepo))
			sendResponse(conn, addr, rmcpSeq, authType, sessionID, sourceAddr, reqSeq, 0x0a, lun, cmd, []byte{0x00, 0x51, byte(c), byte(c >> 8), 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})
		case netFn == 0x0a && cmd == 0x22:
			sendResponse(conn, addr, rmcpSeq, authType, sessionID, sourceAddr, reqSeq, 0x0a, lun, cmd, []byte{0x00, 0x01, 0x00})
		case netFn == 0x0a && cmd == 0x23:
			rid, off, cnt := uint16(ipmiMsg[8])|uint16(ipmiMsg[9])<<8, ipmiMsg[10], ipmiMsg[11]
			idx := int(rid) - 1
			if rid == 0 { idx = 0 }
			if idx < 0 || idx >= len(sdrRepo) { sendResponse(conn, addr, rmcpSeq, authType, sessionID, sourceAddr, reqSeq, 0x0a, lun, cmd, []byte{0xcb}); return }
			sdr, nID := sdrRepo[idx], uint16(idx+2)
			if idx+1 >= len(sdrRepo) { nID = 0xffff }
			dataChunk := make([]byte, cnt)
			for i := 0; i < int(cnt); i++ {
				pos := int(off) + i
				if pos < len(sdr) { dataChunk[i] = sdr[pos] }
			}
			sendResponse(conn, addr, rmcpSeq, authType, sessionID, sourceAddr, reqSeq, 0x0a, lun, cmd, append([]byte{0x00, byte(nID), byte(nID >> 8)}, dataChunk...))
		case netFn == 0x04 && cmd == 0x2d:
			val := byte(38)
			if ipmiMsg[6] == 0x04 { val = 100 }
			sendResponse(conn, addr, rmcpSeq, authType, sessionID, sourceAddr, reqSeq, 0x04, lun, cmd, []byte{0x00, val, 0x40})
		case netFn == 0x06 && cmd == 0x3c:
			sendResponse(conn, addr, rmcpSeq, authType, sessionID, sourceAddr, reqSeq, 0x06, lun, cmd, []byte{0x00})
		default:
			sendResponse(conn, addr, rmcpSeq, authType, sessionID, sourceAddr, reqSeq, netFn, lun, cmd, []byte{0xc1})
		}
	}
}

func sendResponse(conn *net.UDPConn, addr *net.UDPAddr, rmcpSeq, authType byte, sessionID []byte, toolAddr byte, reqSeq, netFn, lun, cmd byte, payload []byte) {
	msg := append([]byte{0x20, ((netFn + 1) << 2) | lun, 0x00, toolAddr, reqSeq, cmd}, payload...)
	msg = append(msg, 0x00)
	msg[2], msg[len(msg)-1] = calculateChecksum(msg[0:2]), calculateChecksum(msg[3:len(msg)-1])
	sessionHeader := []byte{authType}
	seq := seqCounter; seqCounter++
	sessionHeader = append(sessionHeader, byte(seq), byte(seq>>8), byte(seq>>16), byte(seq>>24))
	sessionHeader = append(sessionHeader, sessionID...)
	if authType == 0x01 || authType == 0x02 {
		pwd := make([]byte, 16); copy(pwd, "redborder")
		h := md5.New(); h.Write(pwd); h.Write(sessionID); h.Write(msg); h.Write(sessionHeader[1:5]); h.Write(pwd)
		sessionHeader = append(sessionHeader, h.Sum(nil)...)
	}
	resp := append(append([]byte{0x06, 0x00, rmcpSeq, 0x07}, sessionHeader...), byte(len(msg)))
	conn.WriteToUDP(append(resp, msg...), addr)
}

func calculateChecksum(data []byte) byte {
	var sum byte
	for _, b := range data { sum += b }
	return byte(0 - sum)
}
