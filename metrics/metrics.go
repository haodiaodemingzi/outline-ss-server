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

package metrics

import (
	"io"
	"time"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/prometheus/client_golang/prometheus"
)

// ShadowsocksMetrics registers metrics for the Shadowsocks service.
type ShadowsocksMetrics interface {
	SetNumAccessKeys(numKeys int, numPorts int)
	AddClientUDPPacket(accessKey, status string, clientProxyBytes, proxyTargetBytes int)
	AddTargetUDPPacket(accessKey, status string, targetProxyBytes, proxyClientBytes int)
	AddOpenTCPConnection()
	AddClosedTCPConnection(accessKey, status string, data ProxyMetrics, duration time.Duration)

	AddUdpNatEntry()
	RemoveUdpNatEntry()
}

type shadowsocksMetrics struct {
	accessKeys           prometheus.Gauge
	ports                prometheus.Gauge
	tcpOpenConnections   prometheus.Counter
	tcpClosedConnections *prometheus.CounterVec
	// TODO: Define a time window for the duration summary (e.g. 1 hour)
	tcpConnectionDurationMs *prometheus.SummaryVec

	// TODO: Add per network/location metrics.
	// TODO: Add time to first byte.
	dataBytes *prometheus.CounterVec

	udpAddedNatEntries   prometheus.Counter
	udpRemovedNatEntries prometheus.Counter
}

func NewShadowsocksMetrics() ShadowsocksMetrics {
	m := &shadowsocksMetrics{
		accessKeys: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "shadowsocks",
			Name:      "keys",
			Help:      "Count of access keys",
		}),
		ports: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "shadowsocks",
			Name:      "ports",
			Help:      "Count of open Shadowsocks ports",
		}),
		tcpOpenConnections: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "shadowsocks",
			Subsystem: "tcp",
			Name:      "connections_opened",
			Help:      "Count of open TCP connections",
		}),
		tcpClosedConnections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "shadowsocks",
			Subsystem: "tcp",
			Name:      "connections_closed",
			Help:      "Count of closed TCP connections",
		}, []string{"status", "access_key"}),
		tcpConnectionDurationMs: prometheus.NewSummaryVec(
			prometheus.SummaryOpts{
				Namespace:  "shadowsocks",
				Subsystem:  "tcp",
				Name:       "connection_duration_ms",
				Help:       "TCP connection duration distributions.",
				Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
			}, []string{"status", "access_key"}),
		dataBytes: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "shadowsocks",
				Name:      "data_bytes",
				Help:      "Bytes tranferred by the proxy",
			}, []string{"dir", "proto", "status", "access_key"}),
		udpAddedNatEntries: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "shadowsocks",
				Subsystem: "udp",
				Name:      "nat_entries_added",
				Help:      "Entries added to the UDP NAT table",
			}),
		udpRemovedNatEntries: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "shadowsocks",
				Subsystem: "udp",
				Name:      "nat_entries_removed",
				Help:      "Entries removed from the UDP NAT table",
			}),
	}
	// TODO: Is it possible to pass where to register the collectors?
	prometheus.MustRegister(m.accessKeys, m.ports, m.tcpOpenConnections, m.tcpClosedConnections, m.tcpConnectionDurationMs,
		m.dataBytes, m.udpAddedNatEntries, m.udpRemovedNatEntries)
	return m
}

func (m *shadowsocksMetrics) SetNumAccessKeys(numKeys int, ports int) {
	m.accessKeys.Set(float64(numKeys))
	m.ports.Set(float64(ports))
}

func (m *shadowsocksMetrics) AddOpenTCPConnection() {
	m.tcpOpenConnections.Inc()
}

func (m *shadowsocksMetrics) AddClosedTCPConnection(accessKey, status string, data ProxyMetrics, duration time.Duration) {
	m.tcpClosedConnections.WithLabelValues(status, accessKey).Inc()
	m.tcpConnectionDurationMs.WithLabelValues(status, accessKey).Observe(duration.Seconds() * 1000)
	m.dataBytes.WithLabelValues("c>p", "tcp", status, accessKey).Add(float64(data.ClientProxy))
	m.dataBytes.WithLabelValues("p>t", "tcp", status, accessKey).Add(float64(data.ProxyTarget))
	m.dataBytes.WithLabelValues("p<t", "tcp", status, accessKey).Add(float64(data.TargetProxy))
	m.dataBytes.WithLabelValues("c<p", "tcp", status, accessKey).Add(float64(data.ProxyClient))
}

func (m *shadowsocksMetrics) AddClientUDPPacket(accessKey, status string, clientProxyBytes, proxyTargetBytes int) {
	m.dataBytes.WithLabelValues("c>p", "udp", status, accessKey).Add(float64(clientProxyBytes))
	m.dataBytes.WithLabelValues("p>t", "udp", status, accessKey).Add(float64(proxyTargetBytes))
}

func (m *shadowsocksMetrics) AddTargetUDPPacket(accessKey, status string, targetProxyBytes, proxyClientBytes int) {
	m.dataBytes.WithLabelValues("p<t", "udp", status, accessKey).Add(float64(targetProxyBytes))
	m.dataBytes.WithLabelValues("c<p", "udp", status, accessKey).Add(float64(proxyClientBytes))
}

func (m *shadowsocksMetrics) AddUdpNatEntry() {
	m.udpAddedNatEntries.Inc()
}

func (m *shadowsocksMetrics) RemoveUdpNatEntry() {
	m.udpRemovedNatEntries.Inc()
}

type ProxyMetrics struct {
	ClientProxy int64
	ProxyTarget int64
	TargetProxy int64
	ProxyClient int64
}

func (m *ProxyMetrics) add(other ProxyMetrics) {
	m.ClientProxy += other.ClientProxy
	m.ProxyTarget += other.ProxyTarget
	m.TargetProxy += other.TargetProxy
	m.ProxyClient += other.ProxyClient
}

type measuredConn struct {
	onet.DuplexConn
	io.WriterTo
	readCount *int64
	io.ReaderFrom
	writeCount *int64
}

func (c *measuredConn) Read(b []byte) (int, error) {
	n, err := c.DuplexConn.Read(b)
	*c.readCount += int64(n)
	return n, err
}

func (c *measuredConn) WriteTo(w io.Writer) (int64, error) {
	n, err := io.Copy(w, c.DuplexConn)
	*c.readCount += n
	return n, err
}

func (c *measuredConn) Write(b []byte) (int, error) {
	n, err := c.DuplexConn.Write(b)
	*c.writeCount += int64(n)
	return n, err
}

func (c *measuredConn) ReadFrom(r io.Reader) (int64, error) {
	n, err := io.Copy(c.DuplexConn, r)
	*c.writeCount += n
	return n, err
}

func MeasureConn(conn onet.DuplexConn, bytesSent, bytesRceived *int64) onet.DuplexConn {
	return &measuredConn{DuplexConn: conn, writeCount: bytesSent, readCount: bytesRceived}
}
