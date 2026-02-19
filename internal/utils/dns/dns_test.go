package dns

import (
	"errors"
	"net"
	"reflect"
	"testing"
	"time"
)

// --- Mocking for net.LookupTXT ---
var mockTXTRecords map[string][]string
var mockLookupTXTErr error

func setupMockLookupTXT(t *testing.T, records map[string][]string, err error) {
	mockTXTRecords = records
	mockLookupTXTErr = err
	LookupTXTFunc = func(name string) ([]string, error) {
		t.Logf("DEBUG: LookupTXTFunc called for name: %s, mockLookupTXTErr: %v, mockTXTRecords[%s]: %v", name, mockLookupTXTErr, name, mockTXTRecords[name])
		if records, ok := mockTXTRecords[name]; ok { // Check mockTXTRecords first
			return records, nil
		}
		if mockLookupTXTErr != nil { // Then check global error
			return nil, mockLookupTXTErr
		}
		return nil, errors.New("host not found") // Simulate NXDOMAIN
	}
}

func teardownMockLookupTXT() {
	LookupTXTFunc = net.LookupTXT // Reset to original
	mockTXTRecords = nil
	mockLookupTXTErr = nil
}

// --- Mocking for net.LookupMX ---
var mockMXRecords map[string][]*net.MX
var mockLookupMXErr error

func setupMockLookupMX(records map[string][]*net.MX, err error) {
	mockMXRecords = records
	mockLookupMXErr = err
	LookupMXFunc = func(name string) ([]*net.MX, error) {
		if mockLookupMXErr != nil {
			return nil, mockLookupMXErr
		}
		if records, ok := mockMXRecords[name]; ok {
			return records, nil
		}
		return nil, errors.New("host not found") // Simulate NXDOMAIN
	}
}

func teardownMockLookupMX() {
	LookupMXFunc = net.LookupMX // Reset to original
	mockMXRecords = nil
	mockLookupMXErr = nil
}

// --- Mocking for net.LookupIP ---
var mockIPs map[string][]net.IP
var mockLookupIPErr error

func setupMockLookupIP(ips map[string][]net.IP, err error) {
	mockIPs = ips
	mockLookupIPErr = err
	LookupIPFunc = func(name string) ([]net.IP, error) {
		if mockLookupIPErr != nil {
			return nil, mockLookupIPErr
		}
		if ipList, ok := mockIPs[name]; ok {
			return ipList, nil
		}
		return nil, errors.New("host not found")
	}
}

func teardownMockLookupIP() {
	LookupIPFunc = net.LookupIP
	mockIPs = nil
	mockLookupIPErr = nil
}

// --- Mocking for net.LookupAddr ---
var mockAddrs map[string][]string
var mockLookupAddrErr error

func setupMockLookupAddr(addrs map[string][]string, err error) {
	mockAddrs = addrs
	mockLookupAddrErr = err
	LookupAddrFunc = func(addr string) ([]string, error) {
		if mockLookupAddrErr != nil {
			return nil, mockLookupAddrErr
		}
		if addrList, ok := mockAddrs[addr]; ok {
			return addrList, nil
		}
		return nil, errors.New("not found")
	}
}

func teardownMockLookupAddr() {
	LookupAddrFunc = net.LookupAddr
	mockAddrs = nil
	mockLookupAddrErr = nil
}

func TestVerifySPF_NewMechanisms(t *testing.T) {
	tests := []struct {
		name           string
		ip             string
		domain         string
		sender         string
		mockTXT        map[string][]string
		mockMX         map[string][]*net.MX
		mockIP         map[string][]net.IP
		mockAddr       map[string][]string
		expectedResult SPFResult
	}{
		{
			name:   "A mechanism match",
			ip:     "1.2.3.4",
			domain: "example.com",
			sender: "sender@example.com",
			mockTXT: map[string][]string{
				"example.com": {"v=spf1 a -all"},
			},
			mockIP: map[string][]net.IP{
				"example.com": {net.ParseIP("1.2.3.4")},
			},
			expectedResult: SPFPass,
		},
		{
			name:   "A:domain mechanism match",
			ip:     "1.2.3.4",
			domain: "example.com",
			sender: "sender@example.com",
			mockTXT: map[string][]string{
				"example.com": {"v=spf1 a:other.com -all"},
			},
			mockIP: map[string][]net.IP{
				"other.com": {net.ParseIP("1.2.3.4")},
			},
			expectedResult: SPFPass,
		},
		{
			name:   "MX mechanism match",
			ip:     "1.2.3.4",
			domain: "example.com",
			sender: "sender@example.com",
			mockTXT: map[string][]string{
				"example.com": {"v=spf1 mx -all"},
			},
			mockMX: map[string][]*net.MX{
				"example.com": {{Host: "mail.example.com"}},
			},
			mockIP: map[string][]net.IP{
				"mail.example.com": {net.ParseIP("1.2.3.4")},
			},
			expectedResult: SPFPass,
		},
		{
			name:   "PTR mechanism match",
			ip:     "1.2.3.4",
			domain: "example.com",
			sender: "sender@example.com",
			mockTXT: map[string][]string{
				"example.com": {"v=spf1 ptr -all"},
			},
			mockAddr: map[string][]string{
				"1.2.3.4": {"mail.example.com."},
			},
			mockIP: map[string][]net.IP{
				"mail.example.com": {net.ParseIP("1.2.3.4")},
			},
			expectedResult: SPFPass,
		},
		{
			name:   "Exists mechanism match",
			ip:     "1.2.3.4",
			domain: "example.com",
			sender: "sender@example.com",
			mockTXT: map[string][]string{
				"example.com": {"v=spf1 exists:check.com -all"},
			},
			mockIP: map[string][]net.IP{
				"check.com": {net.ParseIP("127.0.0.1")},
			},
			expectedResult: SPFPass,
		},
		{
			name:   "A mechanism no match",
			ip:     "1.2.3.5",
			domain: "example.com",
			sender: "sender@example.com",
			mockTXT: map[string][]string{
				"example.com": {"v=spf1 a -all"},
			},
			mockIP: map[string][]net.IP{
				"example.com": {net.ParseIP("1.2.3.4")},
			},
			expectedResult: SPFFail,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupMockLookupTXT(t, tt.mockTXT, nil)
			setupMockLookupMX(tt.mockMX, nil)
			setupMockLookupIP(tt.mockIP, nil)
			setupMockLookupAddr(tt.mockAddr, nil)
			defer teardownMockLookupTXT()
			defer teardownMockLookupMX()
			defer teardownMockLookupIP()
			defer teardownMockLookupAddr()

			result, _ := VerifySPF(tt.ip, tt.domain, SPFMacroContext{Sender: tt.sender})
			if result != tt.expectedResult {
				t.Errorf("VerifySPF() got = %v, want %v", result, tt.expectedResult)
			}
		})
	}
}

func TestVerifySPF(t *testing.T) {
	tests := []struct {
		name           string
		ip             string
		domain         string
		sender         string
		mockRecords    map[string][]string
		mockErr        error
		expectedResult SPFResult
	}{
		{
			name:           "Exact IPv4 match (implicit +)",
			ip:             "192.168.1.1",
			domain:         "example.com",
			sender:         "sender@example.com",
			mockRecords:    map[string][]string{"example.com": {"v=spf1 ip4:192.168.1.1 -all"}},
			expectedResult: SPFPass,
		},
		{
			name:           "Exact IPv4 match (+ qualifier)",
			ip:             "192.168.1.1",
			domain:         "example.com",
			sender:         "sender@example.com",
			mockRecords:    map[string][]string{"example.com": {"v=spf1 +ip4:192.168.1.1 -all"}},
			expectedResult: SPFPass,
		},
		{
			name:           "IPv4 CIDR match",
			ip:             "192.168.1.5",
			domain:         "example.com",
			sender:         "sender@example.com",
			mockRecords:    map[string][]string{"example.com": {"v=spf1 ip4:192.168.1.0/24 -all"}},
			expectedResult: SPFPass,
		},
		{
			name:           "IPv4 CIDR no match",
			ip:             "192.168.2.5",
			domain:         "example.com",
			sender:         "sender@example.com",
			mockRecords:    map[string][]string{"example.com": {"v=spf1 ip4:192.168.1.0/24 -all"}},
			expectedResult: SPFFail,
		},
		{
			name:           "Exact IPv6 match",
			ip:             "2001:0db8::1",
			domain:         "example.com",
			sender:         "sender@example.com",
			mockRecords:    map[string][]string{"example.com": {"v=spf1 ip6:2001:0db8::1 -all"}},
			expectedResult: SPFPass,
		},
		{
			name:           "IPv6 CIDR match",
			ip:             "2001:0db8::f00d",
			domain:         "example.com",
			sender:         "sender@example.com",
			mockRecords:    map[string][]string{"example.com": {"v=spf1 ip6:2001:0db8::/32 -all"}},
			expectedResult: SPFPass,
		},
		{
			name:           "IPv6 CIDR no match",
			ip:             "2001:0db9::f00d",
			domain:         "example.com",
			sender:         "sender@example.com",
			mockRecords:    map[string][]string{"example.com": {"v=spf1 ip6:2001:0db8::/32 -all"}},
			expectedResult: SPFFail,
		},
		{
			name:           "No SPF record, none",
			ip:             "1.1.1.1",
			domain:         "example.com",
			sender:         "sender@example.com",
			mockRecords:    map[string][]string{"example.com": {"someothertxtrecord"}},
			expectedResult: SPFNone,
		},
		{
			name:           "SPF record but no match, -all",
			ip:             "1.1.1.1",
			domain:         "example.com",
			sender:         "sender@example.com",
			mockRecords:    map[string][]string{"example.com": {"v=spf1 ip4:2.2.2.2 -all"}},
			expectedResult: SPFFail,
		},
		{
			name:           "SPF record but no match, ~all",
			ip:             "1.1.1.1",
			domain:         "example.com",
			sender:         "sender@example.com",
			mockRecords:    map[string][]string{"example.com": {"v=spf1 ip4:2.2.2.2 ~all"}},
			expectedResult: SPFSoftFail,
		},
		{
			name:           "SPF record but no match, ?all",
			ip:             "1.1.1.1",
			domain:         "example.com",
			sender:         "sender@example.com",
			mockRecords:    map[string][]string{"example.com": {"v=spf1 ip4:2.2.2.2 ?all"}},
			expectedResult: SPFNeutral,
		},
		{
			name:   "Include mechanism - pass",
			ip:     "10.0.0.1",
			domain: "example.com",
			sender: "sender@example.com",
			mockRecords: map[string][]string{
				"example.com":     {"v=spf1 include:sub.example.com -all"},
				"sub.example.com": {"v=spf1 ip4:10.0.0.0/24 -all"},
			},
			expectedResult: SPFPass,
		},
		{
			name:   "Include mechanism - fail from sub-domain",
			ip:     "10.0.1.1",
			domain: "example.com",
			sender: "sender@example.com",
			mockRecords: map[string][]string{
				"example.com":     {"v=spf1 include:sub.example.com -all"},
				"sub.example.com": {"v=spf1 ip4:10.0.0.0/24 -all"},
			},
			expectedResult: SPFFail,
		},
		{
			name:   "Redirect mechanism - pass",
			ip:     "10.0.0.1",
			domain: "example.com",
			sender: "sender@example.com",
			mockRecords: map[string][]string{
				"example.com":     {"v=spf1 redirect=sub.example.com"},
				"sub.example.com": {"v=spf1 ip4:10.0.0.0/24 -all"},
			},
			expectedResult: SPFPass,
		},
		{
			name:   "Redirect mechanism - fail from sub-domain",
			ip:     "10.0.1.1",
			domain: "example.com",
			sender: "sender@example.com",
			mockRecords: map[string][]string{
				"example.com":     {"v=spf1 redirect=sub.example.com"},
				"sub.example.com": {"v=spf1 ip4:10.0.0.0/24 -all"},
			},
			expectedResult: SPFFail,
		},
		{
			name:           "Complex record with multiple mechanisms - match first",
			ip:             "192.168.1.10",
			domain:         "example.com",
			sender:         "sender@example.com",
			mockRecords:    map[string][]string{"example.com": {"v=spf1 ip4:192.168.1.0/24 ip4:10.0.0.0/8 -all"}},
			expectedResult: SPFPass,
		},
		{
			name:           "Complex record with multiple mechanisms - match second",
			ip:             "10.0.0.10",
			domain:         "example.com",
			sender:         "sender@example.com",
			mockRecords:    map[string][]string{"example.com": {"v=spf1 ip4:192.168.1.0/24 ip4:10.0.0.0/8 -all"}},
			expectedResult: SPFPass,
		},
		{
			name:   "Complex record with include and all",
			ip:     "172.16.0.5",
			domain: "example.com",
			sender: "sender@example.com",
			mockRecords: map[string][]string{
				"example.com": {"v=spf1 ip4:192.168.1.0/24 include:other.com ~all"},
				"other.com":   {"v=spf1 ip4:172.16.0.0/16 -all"},
				"another.com": {"v=spf1 ip4:1.2.3.4 -all"},
			},
			expectedResult: SPFPass,
		},
		{
			name:   "Complex record with include, no match, then ~all",
			ip:     "1.1.1.1",
			domain: "example.com",
			sender: "sender@example.com",
			mockRecords: map[string][]string{
				"example.com": {"v=spf1 ip4:192.168.1.0/24 include:other.com ~all"},
				"other.com":   {"v=spf1 ip4:172.16.0.0/16 -all"},
			},
			expectedResult: SPFSoftFail,
		},
		{
			name:           "DNS lookup error for main domain",
			ip:             "1.1.1.1",
			domain:         "example.com",
			sender:         "sender@example.com",
			mockRecords:    nil,
			mockErr:        errors.New("lookup example.com: server failed"),
			expectedResult: SPFTempError,
		},
		{
			name:   "DNS lookup error for included domain",
			ip:     "1.1.1.1",
			domain: "example.com",
			sender: "sender@example.com",
			mockRecords: map[string][]string{
				"example.com": {"v=spf1 include:nonexistent.com -all"},
			},
			mockErr:        errors.New("lookup nonexistent.com: no such host"), // Simulate error for include
			expectedResult: SPFPermError,
		},
		{
			name:   "Max recursion depth reached for include",
			ip:     "1.1.1.1",
			domain: "example.com",
			sender: "sender@example.com",
			mockRecords: map[string][]string{
				"example.com":       {"v=spf1 include:sub1.example.com -all"},
				"sub1.example.com":  {"v=spf1 include:sub2.example.com -all"},
				"sub2.example.com":  {"v=spf1 include:sub3.example.com -all"},
				"sub3.example.com":  {"v=spf1 include:sub4.example.com -all"},
				"sub4.example.com":  {"v=spf1 include:sub5.example.com -all"},
				"sub5.example.com":  {"v=spf1 include:sub6.example.com -all"},
				"sub6.example.com":  {"v=spf1 include:sub7.example.com -all"},
				"sub7.example.com":  {"v=spf1 include:sub8.example.com -all"},
				"sub8.example.com":  {"v=spf1 include:sub9.example.com -all"},
				"sub9.example.com":  {"v=spf1 include:sub10.example.com -all"},
				"sub10.example.com": {"v=spf1 include:sub11.example.com -all"}, // This will trigger max depth
				"sub11.example.com": {"v=spf1 ip4:1.1.1.1 -all"},
			},
			expectedResult: SPFPermError,
		},
		{
			name:           "Invalid IP provided",
			ip:             "invalid-ip",
			domain:         "example.com",
			sender:         "sender@example.com",
			mockRecords:    map[string][]string{"example.com": {"v=spf1 ip4:1.1.1.1 -all"}},
			expectedResult: SPFPermError,
		},
		{
			name:           "Multiple SPF records",
			ip:             "192.168.1.1",
			domain:         "example.com",
			sender:         "sender@example.com",
			mockRecords:    map[string][]string{"example.com": {"v=spf1 ip4:192.168.1.1 -all", "v=spf1 ip4:1.2.3.4 -all"}},
			expectedResult: SPFPermError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupMockLookupTXT(t, tt.mockRecords, tt.mockErr)
			defer teardownMockLookupTXT()

			result, err := VerifySPF(tt.ip, tt.domain, SPFMacroContext{Sender: tt.sender})

			if err != nil && tt.mockErr == nil {
				t.Errorf("VerifySPF() unexpected error = %v", err)
			}
			if result != tt.expectedResult {
				t.Errorf("VerifySPF() got = %v, want %v", result, tt.expectedResult)
			}
		})
	}
}

func TestVerifySPF_MacroSupport(t *testing.T) {
	tests := []struct {
		name           string
		ip             string
		domain         string
		sender         string
		helo           string
		mockTXT        map[string][]string
		mockIP         map[string][]net.IP
		mockAddr       map[string][]string
		expectedResult SPFResult
	}{
		{
			name:   "Include with %{d2} expands to parent domain",
			ip:     "1.2.3.4",
			domain: "mail.example.com",
			sender: "sender@mail.example.com",
			helo:   "mail.example.com",
			mockTXT: map[string][]string{
				"mail.example.com": {"v=spf1 include:%{d2} -all"},
				"example.com":      {"v=spf1 ip4:1.2.3.4 -all"},
			},
			expectedResult: SPFPass,
		},
		{
			name:   "Exists with %{i} expands to IP-based name",
			ip:     "1.2.3.4",
			domain: "example.com",
			sender: "sender@example.com",
			helo:   "mail.example.com",
			mockTXT: map[string][]string{
				"example.com": {"v=spf1 exists:%{i}.spf.example.com -all"},
			},
			mockIP: map[string][]net.IP{
				"1.2.3.4.spf.example.com": {net.ParseIP("127.0.0.1")},
			},
			expectedResult: SPFPass,
		},
		{
			name:   "Exists with %{d2r} reverses and truncates",
			ip:     "1.1.1.1",
			domain: "a.b.example.com",
			sender: "sender@a.b.example.com",
			helo:   "mail.example.com",
			mockTXT: map[string][]string{
				"a.b.example.com": {"v=spf1 exists:%{d2r}.spf.test -all"},
			},
			mockIP: map[string][]net.IP{
				"com.example.spf.test": {net.ParseIP("127.0.0.1")},
			},
			expectedResult: SPFPass,
		},
		{
			name:   "Exists with %{l} and %{o}",
			ip:     "1.1.1.1",
			domain: "example.com",
			sender: "user+tag@example.com",
			helo:   "mail.example.com",
			mockTXT: map[string][]string{
				"example.com": {"v=spf1 exists:%{l}.%{o} -all"},
			},
			mockIP: map[string][]net.IP{
				"user.tag.example.com": {net.ParseIP("127.0.0.1")},
			},
			expectedResult: SPFPass,
		},
		{
			name:   "Exists with %{p} validated PTR",
			ip:     "1.2.3.4",
			domain: "example.com",
			sender: "sender@example.com",
			helo:   "mail.example.com",
			mockTXT: map[string][]string{
				"example.com": {"v=spf1 exists:%{p} -all"},
			},
			mockAddr: map[string][]string{
				"1.2.3.4": {"raw.example.com.", "ptr.example.com."},
			},
			mockIP: map[string][]net.IP{
				"ptr.example.com": {net.ParseIP("1.2.3.4")},
				"raw.example.com": {net.ParseIP("8.8.8.8")},
			},
			expectedResult: SPFPass,
		},
		{
			name:   "Exists with %{r} raw PTR",
			ip:     "1.2.3.5",
			domain: "example.com",
			sender: "sender@example.com",
			helo:   "mail.example.com",
			mockTXT: map[string][]string{
				"example.com": {"v=spf1 exists:%{r} -all"},
			},
			mockAddr: map[string][]string{
				"1.2.3.5": {"raw.example.com."},
			},
			mockIP: map[string][]net.IP{
				"raw.example.com": {net.ParseIP("127.0.0.1")},
			},
			expectedResult: SPFPass,
		},
		{
			name:   "Unsupported macro yields permerror",
			ip:     "1.1.1.1",
			domain: "example.com",
			sender: "sender@example.com",
			helo:   "mail.example.com",
			mockTXT: map[string][]string{
				"example.com": {"v=spf1 exists:%{x} -all"},
			},
			expectedResult: SPFPermError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupMockLookupTXT(t, tt.mockTXT, nil)
			setupMockLookupIP(tt.mockIP, nil)
			setupMockLookupAddr(tt.mockAddr, nil)
			defer teardownMockLookupTXT()
			defer teardownMockLookupIP()
			defer teardownMockLookupAddr()

			result, _ := VerifySPF(tt.ip, tt.domain, SPFMacroContext{Sender: tt.sender, Helo: tt.helo})
			if result != tt.expectedResult {
				t.Errorf("VerifySPF() got = %v, want %v", result, tt.expectedResult)
			}
		})
	}
}

func TestExpandSPFMacrosIPv6(t *testing.T) {
	ctx := macroContext{
		ipStr:  "2001:0db8::1",
		ip:     net.ParseIP("2001:0db8::1"),
		domain: "example.com",
		sender: "sender@example.com",
		helo:   "mail.example.com",
		now:    time.Unix(1700000000, 0).UTC(),
	}

	got, err := expandSPFMacros("%{i}", &ctx)
	if err != nil {
		t.Fatalf("expandSPFMacros() unexpected error: %v", err)
	}

	want := "2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1"
	if got != want {
		t.Fatalf("expandSPFMacros() got = %s, want %s", got, want)
	}
}

func TestExpandSPFMacrosExtended(t *testing.T) {
	setupMockLookupAddr(map[string][]string{
		"1.2.3.4": {"raw.example.com.", "ptr.example.com."},
	}, nil)
	setupMockLookupIP(map[string][]net.IP{
		"ptr.example.com": {net.ParseIP("1.2.3.4")},
		"raw.example.com": {net.ParseIP("8.8.8.8")},
	}, nil)
	defer teardownMockLookupAddr()
	defer teardownMockLookupIP()

	ctx := macroContext{
		ipStr:  "1.2.3.4",
		ip:     net.ParseIP("1.2.3.4"),
		domain: "example.com",
		sender: "user+tag@example.com",
		helo:   "mail.sender.tld",
		now:    time.Unix(1700000000, 0).UTC(),
	}

	got, err := expandSPFMacros("%{l}.%{o}.%{h}.%{p}.%{r}.%{t}.%{v}.%{c}", &ctx)
	if err != nil {
		t.Fatalf("expandSPFMacros() unexpected error: %v", err)
	}

	want := "user.tag.example.com.mail.sender.tld.ptr.example.com.raw.example.com.1700000000.in-addr.1.2.3.4"
	if got != want {
		t.Fatalf("expandSPFMacros() got = %s, want %s", got, want)
	}
}

func TestVerifyDMARC(t *testing.T) {
	tests := []struct {
		name           string
		headerFrom     string
		spfResult      SPFResult
		spfDomain      string
		dkimDomains    []string
		sampleKey      string
		mockRecords    map[string][]string
		mockErr        error
		expectedPass   bool
		expectedPolicy string
	}{
		{
			name:           "DMARC record with p=reject, SPF aligned",
			headerFrom:     "example.com",
			spfResult:      SPFPass,
			spfDomain:      "example.com",
			dkimDomains:    nil,
			sampleKey:      "a",
			mockRecords:    map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject; rua=mailto:a@example.com"}},
			expectedPass:   true,
			expectedPolicy: "reject",
		},
		{
			name:           "DMARC record with p=reject, SPF not aligned",
			headerFrom:     "example.com",
			spfResult:      SPFPass,
			spfDomain:      "mailer.example.net",
			dkimDomains:    nil,
			sampleKey:      "b",
			mockRecords:    map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject; rua=mailto:a@example.com"}},
			expectedPass:   false,
			expectedPolicy: "reject",
		},
		{
			name:           "DMARC record with p=reject, DKIM aligned",
			headerFrom:     "example.com",
			spfResult:      SPFFail,
			spfDomain:      "example.com",
			dkimDomains:    []string{"example.com"},
			sampleKey:      "c",
			mockRecords:    map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject; rua=mailto:a@example.com"}},
			expectedPass:   true,
			expectedPolicy: "reject",
		},
		{
			name:           "DMARC record with p=quarantine, DKIM not aligned",
			headerFrom:     "example.com",
			spfResult:      SPFFail,
			spfDomain:      "example.com",
			dkimDomains:    []string{"mailer.example.net"},
			sampleKey:      "d",
			mockRecords:    map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=quarantine"}},
			expectedPass:   false,
			expectedPolicy: "quarantine",
		},
		{
			name:           "No DMARC record, SPF not aligned",
			headerFrom:     "example.com",
			spfResult:      SPFPass,
			spfDomain:      "mailer.example.net",
			dkimDomains:    nil,
			sampleKey:      "e",
			mockRecords:    nil, // Simulate no _dmarc TXT record
			mockErr:        errors.New("host not found"),
			expectedPass:   false,
			expectedPolicy: "none",
		},
		{
			name:           "No DMARC record, SPF aligned",
			headerFrom:     "example.com",
			spfResult:      SPFPass,
			spfDomain:      "example.com",
			dkimDomains:    nil,
			sampleKey:      "f",
			mockRecords:    nil, // Simulate no _dmarc TXT record
			mockErr:        errors.New("host not found"),
			expectedPass:   true,
			expectedPolicy: "none",
		},
		{
			name:           "Relaxed SPF alignment allows subdomain",
			headerFrom:     "example.com",
			spfResult:      SPFPass,
			spfDomain:      "mailer.example.com",
			dkimDomains:    nil,
			sampleKey:      "g",
			mockRecords:    map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject; aspf=r"}},
			expectedPass:   true,
			expectedPolicy: "reject",
		},
		{
			name:           "Strict SPF alignment rejects subdomain",
			headerFrom:     "example.com",
			spfResult:      SPFPass,
			spfDomain:      "mailer.example.com",
			dkimDomains:    nil,
			sampleKey:      "h",
			mockRecords:    map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject; aspf=s"}},
			expectedPass:   false,
			expectedPolicy: "reject",
		},
		{
			name:           "Strict DKIM alignment rejects subdomain",
			headerFrom:     "example.com",
			spfResult:      SPFFail,
			spfDomain:      "example.com",
			dkimDomains:    []string{"mailer.example.com"},
			sampleKey:      "i",
			mockRecords:    map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject; adkim=s"}},
			expectedPass:   false,
			expectedPolicy: "reject",
		},
		{
			name:           "pct=0 disables enforcement",
			headerFrom:     "example.com",
			spfResult:      SPFFail,
			spfDomain:      "example.com",
			dkimDomains:    nil,
			sampleKey:      "j",
			mockRecords:    map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject; pct=0"}},
			expectedPass:   false,
			expectedPolicy: "none",
		},
		{
			name:           "Org domain fallback applies sp for subdomain",
			headerFrom:     "mail.example.com",
			spfResult:      SPFFail,
			spfDomain:      "mail.example.com",
			dkimDomains:    nil,
			sampleKey:      "k",
			mockRecords:    map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject; sp=quarantine"}},
			expectedPass:   false,
			expectedPolicy: "quarantine",
		},
		{
			name:           "Org domain fallback uses p when sp missing",
			headerFrom:     "mail.example.com",
			spfResult:      SPFFail,
			spfDomain:      "mail.example.com",
			dkimDomains:    nil,
			sampleKey:      "l",
			mockRecords:    map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject"}},
			expectedPass:   false,
			expectedPolicy: "reject",
		},
		{
			name:           "Org domain fallback uses PSL for co.uk",
			headerFrom:     "mail.example.co.uk",
			spfResult:      SPFFail,
			spfDomain:      "mail.example.co.uk",
			dkimDomains:    nil,
			sampleKey:      "n",
			mockRecords:    map[string][]string{"_dmarc.example.co.uk": {"v=DMARC1; p=reject; sp=quarantine"}},
			expectedPass:   false,
			expectedPolicy: "quarantine",
		},
		{
			name:           "Org domain fallback uses PSL for com.au",
			headerFrom:     "mail.example.com.au",
			spfResult:      SPFFail,
			spfDomain:      "mail.example.com.au",
			dkimDomains:    nil,
			sampleKey:      "p",
			mockRecords:    map[string][]string{"_dmarc.example.com.au": {"v=DMARC1; p=reject; sp=quarantine"}},
			expectedPass:   false,
			expectedPolicy: "quarantine",
		},
		{
			name:           "Org domain fallback uses psl for .com",
			headerFrom:     "mail.example.com",
			spfResult:      SPFFail,
			spfDomain:      "mail.example.com",
			dkimDomains:    nil,
			sampleKey:      "o",
			mockRecords:    map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject; sp=quarantine"}},
			expectedPass:   false,
			expectedPolicy: "quarantine",
		},
		{
			name:           "Org domain record does not apply sp to org itself",
			headerFrom:     "example.com",
			spfResult:      SPFFail,
			spfDomain:      "example.com",
			dkimDomains:    nil,
			sampleKey:      "m",
			mockRecords:    map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject; sp=quarantine"}},
			expectedPass:   false,
			expectedPolicy: "reject",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupMockLookupTXT(t, tt.mockRecords, tt.mockErr)
			defer teardownMockLookupTXT()

			result, err := VerifyDMARC(tt.headerFrom, tt.spfResult, tt.spfDomain, tt.dkimDomains, tt.sampleKey)

			if err != nil && tt.mockErr == nil {
				t.Errorf("VerifyDMARC() unexpected error = %v", err)
			}

			if result.Pass != tt.expectedPass {
				t.Errorf("VerifyDMARC() got pass = %v, want %v", result.Pass, tt.expectedPass)
			}
			if result.EnforcementPolicy != tt.expectedPolicy {
				t.Errorf("VerifyDMARC() got policy = %v, want %v", result.EnforcementPolicy, tt.expectedPolicy)
			}
		})
	}
}

func TestLookupMX(t *testing.T) {
	tests := []struct {
		name          string
		domain        string
		mockMXRecords map[string][]*net.MX
		mockErr       error
		expectedHosts []string
		expectErr     bool
	}{
		{
			name:   "Single MX record",
			domain: "example.com",
			mockMXRecords: map[string][]*net.MX{
				"example.com": {{Host: "mail.example.com.", Pref: 10}},
			},
			expectedHosts: []string{"mail.example.com"},
			expectErr:     false,
		},
		{
			name:   "Multiple MX records, sorted by preference",
			domain: "example.com",
			mockMXRecords: map[string][]*net.MX{
				"example.com": {
					{Host: "mail1.example.com.", Pref: 10},
					{Host: "mail2.example.com.", Pref: 20},
				},
			},
			// net.LookupMX returns sorted by preference, so we expect the same order
			expectedHosts: []string{"mail1.example.com", "mail2.example.com"},
			expectErr:     false,
		},
		{
			name:          "No MX records",
			domain:        "nonexistent.com",
			mockMXRecords: nil, // Will trigger a lookup error
			mockErr:       errors.New("host not found"),
			expectedHosts: nil,
			expectErr:     true,
		},
		{
			name:          "Lookup error",
			domain:        "error.com",
			mockMXRecords: nil,
			mockErr:       errors.New("lookup error.com: server failed"),
			expectedHosts: nil,
			expectErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupMockLookupMX(tt.mockMXRecords, tt.mockErr)
			defer teardownMockLookupMX()

			hosts, err := LookupMX(tt.domain)

			if (err != nil) != tt.expectErr {
				t.Errorf("LookupMX() error = %v, expectErr %v", err, tt.expectErr)
				return
			}
			if !reflect.DeepEqual(hosts, tt.expectedHosts) {
				t.Errorf("LookupMX() got hosts = %v, want %v", hosts, tt.expectedHosts)
			}
		})
	}
}
