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
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Jigsaw-Code/outline-ss-server/metrics"
	onet "github.com/Jigsaw-Code/outline-ss-server/net"

	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

func findAccessKey(clientConn onet.DuplexConn, cipherList map[string]shadowaead.Cipher) (string, onet.DuplexConn, error) {
	if len(cipherList) == 0 {
		return "", nil, errors.New("Empty cipher list")
	} else if len(cipherList) == 1 {
		for id, cipher := range cipherList {
			reader := shadowaead.NewShadowsocksReader(clientConn, cipher)
			writer := shadowaead.NewShadowsocksWriter(clientConn, cipher)
			return id, onet.WrapConn(clientConn, reader, writer), nil
		}
	}
	// replayBuffer saves the bytes read from shadowConn, in order to allow for replays.
	var replayBuffer bytes.Buffer
	// Try each cipher until we find one that authenticates successfully.
	// This assumes that all ciphers are AEAD.
	// TODO: Reorder list to try previously successful ciphers first for the client IP.
	// TODO: Ban and log client IPs with too many failures too quick to protect against DoS.
	ip, ipStr := getIPFromAddr(clientConn.RemoteAddr())
	now := time.Now().Unix()
	// ip := strings.Split(clientConn.RemoteAddr().String(), ":")[0]
	var meta *IPMeta
	if ip <= 0 {
		return "", nil, errors.New("invalid ip")
	}
	meta, _ = ipCiphers[ip]
	if meta != nil {
		meta.last = now
		if now-meta.second >= 60 {
			meta.second = now
			meta.tries = 0
		}
		if meta.ban {
			if meta.last > meta.banTime {
				meta.ban = false
				logger.Infof("It is time to let %v pass", ipStr)
			} else {
				logger.Debugf("%v still banned, unban after timestamp %v seconds later", ipStr, meta.banTime-now)
				return "", nil, errors.New("banned")
			}
		}
		list := meta.cipherIDList
		for _, id := range list {
			logger.Debugf("In Small List, Trying key %v", id)
			// tmpReader reads first from the replayBuffer and then from clientConn if it needs more
			// bytes. All bytes read from clientConn are saved in replayBuffer for future replays.
			tmpReader := io.MultiReader(bytes.NewReader(replayBuffer.Bytes()), io.TeeReader(clientConn, &replayBuffer))
			cipherReader := shadowaead.NewShadowsocksReader(tmpReader, cipherList[id])
			// Read should read just enough data to authenticate the payload size.
			_, err := cipherReader.Read(make([]byte, 0))
			if err != nil {
				logger.Debugf("In Small List, Failed key %v: %v", id, err)
				continue
			}
			logger.Debugf("In Small List, Selected key %v", id)
			if meta.tries > 1 {
				meta.tries--
			}
			// We don't need to keep storing and replaying the bytes anymore, but we don't want to drop
			// those already read into the replayBuffer.
			ssr := shadowaead.NewShadowsocksReader(io.MultiReader(&replayBuffer, clientConn), cipherList[id])
			ssw := shadowaead.NewShadowsocksWriter(clientConn, cipherList[id])
			return id, onet.WrapConn(clientConn, ssr, ssw).(onet.DuplexConn), nil
		}
	}
	for id, cipher := range cipherList {
		logger.Debugf("Trying key %v", id)
		// tmpReader reads first from the replayBuffer and then from clientConn if it needs more
		// bytes. All bytes read from clientConn are saved in replayBuffer for future replays.
		tmpReader := io.MultiReader(bytes.NewReader(replayBuffer.Bytes()), io.TeeReader(clientConn, &replayBuffer))
		cipherReader := shadowaead.NewShadowsocksReader(tmpReader, cipher)
		// Read should read just enough data to authenticate the payload size.
		_, err := cipherReader.Read(make([]byte, 0))
		if err != nil {
			logger.Debugf("Failed key %v: %v", id, err)
			continue
		}
		if meta != nil {
			meta.cipherIDList = append(meta.cipherIDList, id)
			if meta.tries > 1 {
				meta.tries--
			}
		} else {
			meta = &IPMeta{last: now, second: now, cipherIDList: []string{id}}
			ipCiphers[ip] = meta
		}
		logger.Debugf("Selected key %v", id)
		// We don't need to keep storing and replaying the bytes anymore, but we don't want to drop
		// those already read into the replayBuffer.
		ssr := shadowaead.NewShadowsocksReader(io.MultiReader(&replayBuffer, clientConn), cipher)
		ssw := shadowaead.NewShadowsocksWriter(clientConn, cipher)
		return id, onet.WrapConn(clientConn, ssr, ssw).(onet.DuplexConn), nil
	}
	if meta != nil {
		meta.tries++
		if meta.tries >= 10 {
			// meta.ban = true
			meta.banTime = time.Now().Unix() + 300
			meta.tries = 0
			logger.Infof("ban IP %v, until %v", ipStr, meta.banTime)
		}
	} else {
		meta = &IPMeta{last: now, second: now, cipherIDList: []string{}, tries: 1}
		ipCiphers[ip] = meta
	}
	return "", nil, fmt.Errorf("could not find valid key")
}

func runTCPService(listener *net.TCPListener, ciphers *map[string]shadowaead.Cipher, m metrics.ShadowsocksMetrics, r *net.UDPConn) {
	for {
		var clientConn onet.DuplexConn
		clientConn, err := listener.AcceptTCP()
		if err != nil {
			logger.Debugf("Failed to accept: %v", err)
			continue
		}

		go func() (connError *connectionError) {
			clientLocation, err := m.GetLocation(clientConn.RemoteAddr())
			if err != nil {
				logger.Errorf("Failed location lookup: %v", err)
			}
			logger.Debugf("Got location \"%v\" for IP %v", clientLocation, clientConn.RemoteAddr().String())
			m.AddOpenTCPConnection(clientLocation)
			defer func() {
				if r := recover(); r != nil {
					logger.Errorf("Panic in TCP handler: %v", r)
				}
			}()
			connStart := time.Now()
			clientConn.(*net.TCPConn).SetKeepAlive(true)
			keyID := ""
			var proxyMetrics metrics.ProxyMetrics
			clientConn = metrics.MeasureConn(clientConn, &proxyMetrics.ProxyClient, &proxyMetrics.ClientProxy)
			defer func() {
				connEnd := time.Now()
				connDuration := connEnd.Sub(connStart)
				clientConn.Close()
				status := "OK"
				if connError != nil {
					logger.Debugf("TCP Error: %v: %v", connError.message, connError.cause)
					status = connError.status
				}
				logger.Debugf("Done with status %v, duration %v", status, connDuration)
				t := trafficToJSON(&traffic{
					UserID:   keyID,
					Client:   clientConn.RemoteAddr().String(),
					ReqBytes: proxyMetrics.ProxyTarget,
					ResBytes: proxyMetrics.ProxyClient,
				})
				if r != nil {
					r.Write([]byte(t))
					// _, err := r.Write([]byte(t))
					// if err != nil {
					// 	log.Printf("WARN report traffic failed, err: %v, traffic: %v", err, t)
					// }
				}
				m.AddClosedTCPConnection(clientLocation, keyID, status, proxyMetrics, connDuration)
			}()

			keyID, clientConn, err := findAccessKey(clientConn, *ciphers)
			cleanExpired()
			if err != nil {
				return &connectionError{"ERR_CIPHER", "Failed to find a valid cipher", err}
			}

			tgtAddr, err := socks.ReadAddr(clientConn)
			if err != nil {
				return &connectionError{"ERR_READ_ADDRESS", "Failed to get target address", err}
			}
			tgtTCPAddr, err := net.ResolveTCPAddr("tcp", tgtAddr.String())
			if err != nil {
				return &connectionError{"ERR_RESOLVE_ADDRESS", fmt.Sprintf("Failed to resolve target address %v", tgtAddr.String()), err}
			}
			if !tgtTCPAddr.IP.IsGlobalUnicast() {
				return &connectionError{"ERR_ADDRESS_INVALID", fmt.Sprintf("Target address is not global unicast: %v", tgtAddr.String()), err}
			}

			tgtTCPConn, err := net.DialTCP("tcp", nil, tgtTCPAddr)
			if err != nil {
				return &connectionError{"ERR_CONNECT", "Failed to connect to target", err}
			}
			defer tgtTCPConn.Close()
			tgtTCPConn.SetKeepAlive(true)
			tgtConn := metrics.MeasureConn(tgtTCPConn, &proxyMetrics.ProxyTarget, &proxyMetrics.TargetProxy)

			// TODO: Disable logging in production. This is sensitive.
			logger.Debugf("proxy %s <-> %s", clientConn.RemoteAddr().String(), tgtConn.RemoteAddr().String())
			_, _, err = onet.Relay(clientConn, tgtConn)
			if err != nil {
				return &connectionError{"ERR_RELAY", "Failed to relay traffic", err}
			}
			return nil
		}()
	}
}
