// Copyright 2018 Jigsaw Operations LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Jigsaw-Code/outline-ss-server/metrics"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
	"gopkg.in/yaml.v2"
)

var config struct {
	UDPTimeout time.Duration
}

var ipCiphers = make(map[uint32][]string)

type SSPort struct {
	listener   *net.TCPListener
	packetConn net.PacketConn
	keys       map[string]shadowaead.Cipher
}

type connectionError struct {
	// TODO: create status enums and move to metrics.go
	status  string
	message string
	cause   error
}

type traffic struct {
	UserID   string `json:"userID"`
	Client   string `json:"client"`
	ReqBytes int64  `json:"reqBytes"`
	ResBytes int64  `json:"resBytes"`
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func getIPFromAddr(remoteAddr net.Addr) uint32 {
	var ip uint32 = 0
	switch addr := remoteAddr.(type) {
	case *net.UDPAddr:
	case *net.TCPAddr:
		ip = ip2int(addr.IP)
	}
	return ip
}

func trafficToJSON(t *traffic) string {
	b, err := json.Marshal(t)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	return string(b)
}

// Listen on addr for incoming connections.
func (port *SSPort) run(m metrics.ShadowsocksMetrics, r *net.UDPConn) {
	// TODO: Register initial data metrics at zero.
	go runUDPService(port.packetConn, &port.keys, m)
	runTCPService(port.listener, &port.keys, m, r)
}

type SSServer struct {
	m      metrics.ShadowsocksMetrics
	ports  map[int]*SSPort
	report *net.UDPConn
}

func (s *SSServer) startPort(portNum int) error {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{Port: portNum})
	if err != nil {
		return fmt.Errorf("Failed to start TCP on port %v: %v", portNum, err)
	}
	packetConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: portNum})
	if err != nil {
		return fmt.Errorf("ERROR Failed to start UDP on port %v: %v", portNum, err)
	}
	log.Printf("INFO Listening TCP and UDP on port %v", portNum)
	port := &SSPort{listener: listener, packetConn: packetConn, keys: make(map[string]shadowaead.Cipher)}
	s.ports[portNum] = port
	go port.run(s.m, s.report)
	return nil
}

func (s *SSServer) removePort(portNum int) error {
	port, ok := s.ports[portNum]
	if !ok {
		return fmt.Errorf("Port %v doesn't exist", portNum)
	}
	tcpErr := port.listener.Close()
	udpErr := port.packetConn.Close()
	delete(s.ports, portNum)
	if tcpErr != nil {
		return fmt.Errorf("Failed to close listener on %v: %v", portNum, tcpErr)
	}
	if udpErr != nil {
		return fmt.Errorf("Failed to close packetConn on %v: %v", portNum, udpErr)
	}
	log.Printf("INFO Stopped TCP and UDP on port %v", portNum)
	return nil
}

func (s *SSServer) loadConfig(filename string) error {
	config, err := readConfig(filename)
	if err != nil {
		return fmt.Errorf("Failed to read config file %v: %v", filename, err)
	}

	portChanges := make(map[int]int)
	portKeys := make(map[int]map[string]shadowaead.Cipher)
	for _, keyConfig := range config.Keys {
		portChanges[keyConfig.Port] = 1
		keys, ok := portKeys[keyConfig.Port]
		if !ok {
			keys = make(map[string]shadowaead.Cipher)
			portKeys[keyConfig.Port] = keys
		}
		cipher, err := core.PickCipher(keyConfig.Cipher, nil, keyConfig.Secret)
		if err != nil {
			if err == core.ErrCipherNotSupported {
				return fmt.Errorf("Cipher %v for key %v is not supported", keyConfig.Cipher, keyConfig.ID)
			}
			return fmt.Errorf("Failed to create cipher for key %v: %v", keyConfig.ID, err)
		}
		aead, ok := cipher.(shadowaead.Cipher)
		if !ok {
			return fmt.Errorf("Only AEAD ciphers are supported. Found %v", keyConfig.Cipher)
		}
		keys[keyConfig.ID] = aead
	}
	for port := range s.ports {
		portChanges[port] = portChanges[port] - 1
	}
	for portNum, count := range portChanges {
		if count == -1 {
			if err := s.removePort(portNum); err != nil {
				return fmt.Errorf("Failed to remove port %v: %v", portNum, err)
			}
		} else if count == +1 {
			if err := s.startPort(portNum); err != nil {
				return fmt.Errorf("Failed to start port %v: %v", portNum, err)
			}
		}
	}
	for portNum, keys := range portKeys {
		s.ports[portNum].keys = keys
	}
	log.Printf("INFO Loaded %v access keys", len(config.Keys))
	s.m.SetNumAccessKeys(len(config.Keys), len(portKeys))
	return nil
}

func runSSServer(filename string, reportAddr string) error {
	addr, err := net.ResolveUDPAddr("udp", reportAddr)
	if err != nil {
		return fmt.Errorf("WARN Could not resolve addr: %v", reportAddr)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Printf("WARN Could not dial: %v", reportAddr)
	}

	server := &SSServer{m: metrics.NewShadowsocksMetrics(), ports: make(map[int]*SSPort), report: conn}
	err = server.loadConfig(filename)
	if err != nil {
		return fmt.Errorf("Failed to load config file %v: %v", filename, err)
	}

	sigHup := make(chan os.Signal, 1)
	signal.Notify(sigHup, syscall.SIGHUP)
	go func() {
		for range sigHup {
			log.Printf("Updating config")
			if err := server.loadConfig(filename); err != nil {
				log.Printf("ERROR Could not reload config: %v", err)
			}
		}
	}()
	return nil
}

type Config struct {
	Keys []struct {
		ID     string
		Port   int
		Cipher string
		Secret string
	}
}

func readConfig(filename string) (*Config, error) {
	config := Config{}
	configData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(configData, &config)
	return &config, err
}

func main() {
	var flags struct {
		ConfigFile  string
		MetricsAddr string
		ReportAddr  string
	}
	flag.StringVar(&flags.ConfigFile, "config", "", "config filename")
	flag.StringVar(&flags.MetricsAddr, "metrics", "", "address for the Prometheus metrics")
	flag.DurationVar(&config.UDPTimeout, "udptimeout", 5*time.Minute, "UDP tunnel timeout")
	flag.StringVar(&flags.ReportAddr, "report", "", "address to report traffic")

	flag.Parse()

	if flags.ConfigFile == "" {
		flag.Usage()
		return
	}

	if flags.MetricsAddr != "" {
		http.Handle("/metrics", promhttp.Handler())
		go func() {
			log.Fatal(http.ListenAndServe(flags.MetricsAddr, nil))
		}()
		log.Printf("Metrics on http://%v/metrics", flags.MetricsAddr)
	}

	err := runSSServer(flags.ConfigFile, flags.ReportAddr)
	if err != nil {
		log.Fatal(err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
