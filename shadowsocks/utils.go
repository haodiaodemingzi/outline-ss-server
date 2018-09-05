package shadowsocks

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"time"
)

type traffic struct {
	UserID   string `json:"userID"`
	Client   string `json:"client"`
	ReqBytes int64  `json:"reqBytes"`
	ResBytes int64  `json:"resBytes"`
}

type pair struct {
	ip   uint32
	last int64
}

type IPMeta struct {
	cipherIDList []string
	last         int64
	ban          bool
	tries        int
	second       int64
	banTime      int64
}

var ipCiphers = make(map[uint32]*IPMeta)

func cleanExpired() {
	if len(ipCiphers) < 10000 {
		return
	}
	now := time.Now().Unix()

	var pl []pair
	for k, v := range ipCiphers {
		pl = append(pl, pair{k, v.last})
	}
	sort.Slice(pl, func(i, j int) bool {
		return pl[i].last < pl[j].last
	})

	for _, p := range pl {
		if now-ipCiphers[p.ip].last > 3600 {
			logger.Infof("Clean %v from ipCiphers, last request %v ago", p.ip, now-ipCiphers[p.ip].last)
			delete(ipCiphers, p.ip)
			if len(ipCiphers) < 10000 {
				break
			}
		}
	}
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func getIPFromAddr(remoteAddr net.Addr) (uint32, string) {
	var ip uint32
	var str string
	switch addr := remoteAddr.(type) {
	case *net.UDPAddr:
		str = addr.IP.String()
		ip = ip2int(addr.IP)
	case *net.TCPAddr:
		str = addr.IP.String()
		ip = ip2int(addr.IP)
	}
	return ip, str
}

func trafficToJSON(t *traffic) string {
	b, err := json.Marshal(t)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	return string(b)
}
