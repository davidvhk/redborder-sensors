package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

// Redfish agent version
const Version = "1.7.0"

type Config struct {
	UUID         string            `json:"uuid"`
	Manufacturer string            `json:"manufacturer"`
	Model        string            `json:"model"`
	SerialNumber string            `json:"serial_number"`
	User         string            `json:"user"`
	Password     string            `json:"password"`
	FailRate     int               `json:"fail_rate"`
	Health       map[string]string `json:"health"` // component -> status (OK, Critical, Warning)
}

var currentConfig = Config{
	UUID:         "deafbeef-1234-5678-90ab-cdef12345678",
	Manufacturer: "HPE",
	Model:        "ProLiant DL360 Gen10",
	SerialNumber: "RBS-123456789",
	User:         "redborder",
	Password:     "redborder",
	FailRate:     0,
	Health: map[string]string{
		"System":       "OK",
		"iLO":          "OK",
		"Temperatures": "OK",
		"Fans":         "OK",
		"Storage":      "OK",
		"Bios":         "OK",
		"Power":        "OK",
	},
}

var failRateFlag int

func getHealth(component string) string {
	rate := currentConfig.FailRate
	if failRateFlag > 0 {
		rate = failRateFlag
	}

	if rate > 0 && time.Now().UnixNano()%100 < int64(rate) {
		return "Critical"
	}
	if status, ok := currentConfig.Health[component]; ok {
		return status
	}
	return "OK"
}

func main() {
	listenAddr := flag.String("listen", ":443", "Listen address (default 443 for HTTPS)")
	httpAddr := flag.String("http", ":80", "HTTP listen address")
	configPath := flag.String("config", "", "Path to JSON configuration file")
	flag.IntVar(&failRateFlag, "fail-rate", 0, "Probability (0-100) of returning 'Critical' health")
	flag.Parse()

	if *configPath != "" {
		data, err := os.ReadFile(*configPath)
		if err == nil {
			json.Unmarshal(data, &currentConfig)
			fmt.Printf("[+] Loaded configuration from %s\n", *configPath)
		} else {
			fmt.Printf("[-] Error loading config: %v\n", err)
		}
	}

	fmt.Printf("[+] Redfish Mock Agent %s starting...\n", Version)

	mux := http.NewServeMux()
	mux.HandleFunc("/redfish/v1", handleServiceRoot)
	mux.HandleFunc("/redfish/v1/", handleNotFound)
	mux.HandleFunc("/redfish/v1/Chassis", handleChassisCollection)
	mux.HandleFunc("/redfish/v1/Chassis/", handleChassisCollection)
	mux.HandleFunc("/redfish/v1/Chassis/1", handleChassis)
	mux.HandleFunc("/redfish/v1/Chassis/1/", handleChassis)
	mux.HandleFunc("/redfish/v1/Chassis/1/Thermal", handleThermal)
	mux.HandleFunc("/redfish/v1/Chassis/1/Thermal/", handleThermal)
	mux.HandleFunc("/redfish/v1/Chassis/1/Power", handlePower)
	mux.HandleFunc("/redfish/v1/Chassis/1/Power/", handlePower)
	mux.HandleFunc("/redfish/v1/Systems", handleSystemsCollection)
	mux.HandleFunc("/redfish/v1/Systems/", handleSystemsCollection)
	mux.HandleFunc("/redfish/v1/Systems/1", handleSystem)
	mux.HandleFunc("/redfish/v1/Systems/1/", handleSystem)
	mux.HandleFunc("/redfish/v1/Systems/1/Memory/", handleMemoryCollection)
	mux.HandleFunc("/redfish/v1/Systems/1/Memory/1", handleMemory)
	mux.HandleFunc("/redfish/v1/Managers", handleManagersCollection)
	mux.HandleFunc("/redfish/v1/Managers/", handleManagersCollection)
	mux.HandleFunc("/redfish/v1/Managers/1", handleManager)
	mux.HandleFunc("/redfish/v1/Managers/1/", handleManager)
	mux.HandleFunc("/redfish/v1/Managers/Self", handleManager)
	mux.HandleFunc("/redfish/v1/Managers/Self/EthernetInterfaces", handleEthernetInterfaces)
	mux.HandleFunc("/redfish/v1/Systems/1/Actions/ComputerSystem.Reset", handleSystemReset)
	mux.HandleFunc("/redfish/v1/Systems/Self/Actions/ComputerSystem.Reset", handleSystemReset)

	// Start HTTP server in background
	go func() {
		fmt.Printf("[+] HTTP listening on %s\n", *httpAddr)
		http.ListenAndServe(*httpAddr, authMiddleware(mux))
	}()

	// Generate self-signed cert for HTTPS
	cert, err := generateSelfSignedCert()
	if err != nil {
		fmt.Printf("[-] Error generating self-signed cert: %v\n", err)
		os.Exit(1)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	server := &http.Server{
		Addr:         *listenAddr,
		Handler:      authMiddleware(mux),
		TLSConfig:    tlsConfig,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	fmt.Printf("[+] HTTPS listening on %s\n", *listenAddr)
	if err := server.ListenAndServeTLS("", ""); err != nil {
		fmt.Printf("[-] Error starting HTTPS server: %v\n", err)
		os.Exit(1)
	}
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"redBorder Labs Mock"},
			CommonName:   "rfmock",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certBuf := new(bytes.Buffer)
	pem.Encode(certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyBuf := new(bytes.Buffer)
	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	pem.Encode(keyBuf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b})

	return tls.X509KeyPair(certBuf.Bytes(), keyBuf.Bytes())
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redfish/v1" || r.URL.Path == "/redfish/v1/" {
			next.ServeHTTP(w, r)
			return
		}

		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Redfish"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		pair := strings.SplitN(string(payload), ":", 2)
		if len(pair) != 2 || pair[0] != currentConfig.User || pair[1] != currentConfig.Password {
			fmt.Printf("[!] Unauthorized access attempt for user: %s\n", pair[0])
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("OData-Version", "4.0")
	json.NewEncoder(w).Encode(data)
}

func handleServiceRoot(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("[*] GET %s\n", r.URL.Path)
	resp := map[string]interface{}{
		"@odata.type":    "#ServiceRoot.v1_11_0.ServiceRoot",
		"@odata.id":      "/redfish/v1",
		"Id":             "RootService",
		"Name":           "Root Service",
		"RedfishVersion": "1.11.0",
		"UUID":           currentConfig.UUID,
		"Systems":        map[string]string{"@odata.id": "/redfish/v1/Systems"},
		"Chassis":        map[string]string{"@odata.id": "/redfish/v1/Chassis"},
		"Managers":       map[string]string{"@odata.id": "/redfish/v1/Managers"},
		"Oem": map[string]interface{}{
			"Hpe": map[string]interface{}{
				"System": []map[string]interface{}{
					{"Status": map[string]string{"Health": getHealth("System")}},
				},
				"Manager": []map[string]interface{}{
					{"Status": map[string]string{"Health": getHealth("iLO")}},
				},
			},
		},
	}
	jsonResponse(w, resp)
}

func handleChassisCollection(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("[*] GET %s\n", r.URL.Path)
	resp := map[string]interface{}{
		"@odata.type": "#ChassisCollection.ChassisCollection",
		"@odata.id":   "/redfish/v1/Chassis",
		"Name":        "Chassis Collection",
		"Members@odata.count": 1,
		"Members": []map[string]string{
			{"@odata.id": "/redfish/v1/Chassis/1"},
		},
	}
	jsonResponse(w, resp)
}

func handleChassis(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("[*] GET %s\n", r.URL.Path)
	resp := map[string]interface{}{
		"@odata.type":  "#Chassis.v1_14_0.Chassis",
		"@odata.id":    "/redfish/v1/Chassis/1",
		"Id":           "1",
		"Name":         "Main Chassis",
		"ChassisType":  "RackMount",
		"Manufacturer": currentConfig.Manufacturer,
		"Model":        currentConfig.Model,
		"SerialNumber": currentConfig.SerialNumber,
		"PowerState":   "On",
		"Status": map[string]interface{}{
			"State":  "Enabled",
			"Health": getHealth("System"),
		},
		"Thermal": map[string]string{"@odata.id": "/redfish/v1/Chassis/1/Thermal"},
		"Power":   map[string]string{"@odata.id": "/redfish/v1/Chassis/1/Power"},
	}
	jsonResponse(w, resp)
}

func handleThermal(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("[*] GET %s\n", r.URL.Path)
	resp := map[string]interface{}{
		"@odata.type": "#Thermal.v1_7_0.Thermal",
		"@odata.id":   "/redfish/v1/Chassis/1/Thermal",
		"Id":           "Thermal",
		"Name":         "Thermal",
		"Temperatures": []map[string]interface{}{
			{
				"@odata.id":           "/redfish/v1/Chassis/1/Thermal#/Temperatures/0",
				"MemberId":            "0",
				"Name":                "15-Front Ambient",
				"SensorNumber":        1,
				"ReadingCelsius":      25,
				"CurrentReading":      25, // For ilo-sdk compatibility
				"UpperThresholdFatal": 45,
				"Status": map[string]interface{}{
					"State":  "Enabled",
					"Health": getHealth("Temperatures"),
				},
			},
			{
				"@odata.id":           "/redfish/v1/Chassis/1/Thermal#/Temperatures/1",
				"MemberId":            "1",
				"Name":                "02-CPU 1",
				"SensorNumber":        2,
				"ReadingCelsius":      42,
				"CurrentReading":      42, // For ilo-sdk compatibility
				"UpperThresholdFatal": 90,
				"Status": map[string]interface{}{
					"State":  "Enabled",
					"Health": getHealth("Temperatures"),
				},
			},
		},
		"Fans": []map[string]interface{}{
			{
				"@odata.id":    "/redfish/v1/Chassis/1/Thermal#/Fans/0",
				"MemberId":     "0",
				"Name":         "System Fan 1",
				"Reading":      3200,
				"CurrentReading": 3200, // For ilo-sdk compatibility
				"ReadingUnits": "RPM",
				"Status": map[string]interface{}{
					"State":  "Enabled",
					"Health": getHealth("Fans"),
				},
			},
		},
	}
	jsonResponse(w, resp)
}

func handlePower(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("[*] GET %s\n", r.URL.Path)
	resp := map[string]interface{}{
		"@odata.type": "#Power.v1_6_0.Power",
		"@odata.id":   "/redfish/v1/Chassis/1/Power",
		"Id":           "Power",
		"Name":         "Power",
		"PowerControl": []map[string]interface{}{
			{
				"@odata.id":          "/redfish/v1/Chassis/1/Power#/PowerControl/0",
				"MemberId":           "0",
				"Name":               "System Power Control",
				"PowerConsumedWatts": 150,
				"PowerCapacityWatts": 500,
			},
		},
		"PowerSupplies": []map[string]interface{}{
			{
				"@odata.id":    "/redfish/v1/Chassis/1/Power#/PowerSupplies/0",
				"MemberId":     "0",
				"Name":         "Power Supply 1",
				"PowerState":   "On",
				"Status": map[string]interface{}{
					"State":  "Enabled",
					"Health": getHealth("Power"),
				},
			},
		},
	}
	jsonResponse(w, resp)
}

func handleSystemsCollection(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("[*] GET %s\n", r.URL.Path)
	resp := map[string]interface{}{
		"@odata.type": "#ComputerSystemCollection.ComputerSystemCollection",
		"@odata.id":   "/redfish/v1/Systems",
		"Name":        "Computer System Collection",
		"Members@odata.count": 1,
		"Members": []map[string]string{
			{"@odata.id": "/redfish/v1/Systems/1"},
		},
	}
	jsonResponse(w, resp)
}

func handleSystem(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("[*] GET %s\n", r.URL.Path)
	resp := map[string]interface{}{
		"@odata.type":  "#ComputerSystem.v1_13_0.ComputerSystem",
		"@odata.id":    "/redfish/v1/Systems/1",
		"Id":           "1",
		"Name":         "redBorder Sensor System",
		"SystemType":   "Physical",
		"Manufacturer": currentConfig.Manufacturer,
		"Model":        currentConfig.Model,
		"SerialNumber": currentConfig.SerialNumber,
		"Status": map[string]interface{}{
			"State":  "Enabled",
			"Health": getHealth("System"),
		},
		"PowerState": "On",
		"MemorySummary": map[string]interface{}{
			"TotalSystemMemoryGiB": 16,
			"Status": map[string]interface{}{
				"State":  "Enabled",
				"Health": getHealth("System"),
			},
		},
		"ProcessorSummary": map[string]interface{}{
			"Count": 2,
			"Model": "Mock CPU",
			"Status": map[string]interface{}{
				"State":  "Enabled",
				"Health": getHealth("System"),
			},
		},
		"Oem": map[string]interface{}{
			"Hpe": map[string]interface{}{
				"AggregateHealthStatus": map[string]interface{}{
					"BiosOrHardwareHealth": map[string]interface{}{"Status": map[string]string{"Health": getHealth("Bios")}},
					"Fans":                  map[string]interface{}{"Status": map[string]string{"Health": getHealth("Fans")}},
					"Storage":               map[string]interface{}{"Status": map[string]string{"Health": getHealth("Storage")}},
					"Temperatures":          map[string]interface{}{"Status": map[string]string{"Health": getHealth("Temperatures")}},
				},
			},
		},
		"Actions": map[string]interface{}{
			"#ComputerSystem.Reset": map[string]interface{}{
				"target": "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset",
				"ResetType@Redfish.AllowableValues": []string{
					"On", "ForceOff", "GracefulShutdown", "GracefulRestart", "ForceRestart", "Nmi", "ForceOn", "PushPowerButton",
				},
			},
		},
	}
	jsonResponse(w, resp)
}

func handleMemoryCollection(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("[*] GET %s\n", r.URL.Path)
	resp := map[string]interface{}{
		"@odata.type": "#MemoryCollection.MemoryCollection",
		"@odata.id":   "/redfish/v1/Systems/1/Memory",
		"Name":        "Memory Collection",
		"Members@odata.count": 1,
		"Members": []map[string]string{
			{"@odata.id": "/redfish/v1/Systems/1/Memory/1"},
		},
	}
	jsonResponse(w, resp)
}

func handleMemory(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("[*] GET %s\n", r.URL.Path)
	resp := map[string]interface{}{
		"@odata.type": "#Memory.v1_11_0.Memory",
		"@odata.id":   "/redfish/v1/Systems/1/Memory/1",
		"Id":           "1",
		"Name":         "DIMM 1",
		"Status": map[string]interface{}{
			"State":  "Enabled",
			"Health": getHealth("System"),
		},
	}
	jsonResponse(w, resp)
}

func handleManagersCollection(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("[*] GET %s\n", r.URL.Path)
	resp := map[string]interface{}{
		"@odata.type": "#ManagerCollection.ManagerCollection",
		"@odata.id":   "/redfish/v1/Managers",
		"Name":        "Manager Collection",
		"Members@odata.count": 1,
		"Members": []map[string]string{
			{"@odata.id": "/redfish/v1/Managers/1"},
		},
	}
	jsonResponse(w, resp)
}

func handleManager(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("[*] GET %s\n", r.URL.Path)
	resp := map[string]interface{}{
		"@odata.type":  "#Manager.v1_11_0.Manager",
		"@odata.id":    "/redfish/v1/Managers/1",
		"Id":           "1",
		"Name":         "BMC Manager",
		"ManagerType":  "BMC",
		"Manufacturer": currentConfig.Manufacturer,
		"Model":        "RB-BMC-v1",
		"FirmwareVersion": "1.0.0",
		"Status": map[string]interface{}{
			"State":  "Enabled",
			"Health": getHealth("iLO"),
		},
		"EthernetInterfaces": map[string]string{"@odata.id": "/redfish/v1/Managers/1/EthernetInterfaces"},
	}
	jsonResponse(w, resp)
}

func handleEthernetInterfaces(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("[*] GET %s\n", r.URL.Path)
	resp := map[string]interface{}{
		"@odata.type": "#EthernetInterfaceCollection.EthernetInterfaceCollection",
		"@odata.id":   "/redfish/v1/Managers/1/EthernetInterfaces",
		"Name":        "Ethernet Interface Collection",
		"Members@odata.count": 1,
		"Members": []map[string]string{
			{"@odata.id": "/redfish/v1/Managers/1/EthernetInterfaces/1"},
		},
	}
	jsonResponse(w, resp)
}

func handleSystemReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	fmt.Printf("[!] POST %s (Reset Action)\n", r.URL.Path)
	w.WriteHeader(http.StatusNoContent)
}

func handleNotFound(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/redfish/v1" || r.URL.Path == "/redfish/v1/" {
		handleServiceRoot(w, r)
		return
	}
	fmt.Printf("[!] 404 Not Found: %s\n", r.URL.Path)
	w.WriteHeader(http.StatusNotFound)
	resp := map[string]interface{}{
		"error": map[string]interface{}{
			"code":    "Base.1.0.ResourceNotFound",
			"message": "The resource at the specified URI was not found.",
		},
	}
	jsonResponse(w, resp)
}
