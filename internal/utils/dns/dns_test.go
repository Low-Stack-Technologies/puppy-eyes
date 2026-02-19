package dns

import (
	"errors"
	"net"
	"reflect"
	"testing"
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
		name         string
		ip           string
		domain       string
		mockTXT      map[string][]string
		mockMX       map[string][]*net.MX
		mockIP       map[string][]net.IP
		mockAddr     map[string][]string
		expectedPass bool
	}{
		{
			name:   "A mechanism match",
			ip:     "1.2.3.4",
			domain: "example.com",
			mockTXT: map[string][]string{
				"example.com": {"v=spf1 a -all"},
			},
			mockIP: map[string][]net.IP{
				"example.com": {net.ParseIP("1.2.3.4")},
			},
			expectedPass: true,
		},
		{
			name:   "A:domain mechanism match",
			ip:     "1.2.3.4",
			domain: "example.com",
			mockTXT: map[string][]string{
				"example.com": {"v=spf1 a:other.com -all"},
			},
			mockIP: map[string][]net.IP{
				"other.com": {net.ParseIP("1.2.3.4")},
			},
			expectedPass: true,
		},
		{
			name:   "MX mechanism match",
			ip:     "1.2.3.4",
			domain: "example.com",
			mockTXT: map[string][]string{
				"example.com": {"v=spf1 mx -all"},
			},
			mockMX: map[string][]*net.MX{
				"example.com": {{Host: "mail.example.com"}},
			},
			mockIP: map[string][]net.IP{
				"mail.example.com": {net.ParseIP("1.2.3.4")},
			},
			expectedPass: true,
		},
		{
			name:   "PTR mechanism match",
			ip:     "1.2.3.4",
			domain: "example.com",
			mockTXT: map[string][]string{
				"example.com": {"v=spf1 ptr -all"},
			},
			mockAddr: map[string][]string{
				"1.2.3.4": {"mail.example.com."},
			},
			mockIP: map[string][]net.IP{
				"mail.example.com": {net.ParseIP("1.2.3.4")},
			},
			expectedPass: true,
		},
		{
			name:   "Exists mechanism match",
			ip:     "1.2.3.4",
			domain: "example.com",
			mockTXT: map[string][]string{
				"example.com": {"v=spf1 exists:check.com -all"},
			},
			mockIP: map[string][]net.IP{
				"check.com": {net.ParseIP("127.0.0.1")},
			},
			expectedPass: true,
		},
		{
			name:   "A mechanism no match",
			ip:     "1.2.3.5",
			domain: "example.com",
			mockTXT: map[string][]string{
				"example.com": {"v=spf1 a -all"},
			},
			mockIP: map[string][]net.IP{
				"example.com": {net.ParseIP("1.2.3.4")},
			},
			expectedPass: false,
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

			pass, _ := VerifySPF(tt.ip, tt.domain)
			if pass != tt.expectedPass {
				t.Errorf("VerifySPF() got = %v, want %v", pass, tt.expectedPass)
			}
		})
	}
}

func TestVerifySPF(t *testing.T) {
	tests := []struct {
		name         string
		ip           string
		domain       string
		mockRecords  map[string][]string
		mockErr      error
		expectedPass bool
	}{
		{
			name:         "Exact IPv4 match (implicit +)",
			ip:           "192.168.1.1",
			domain:       "example.com",
			mockRecords:  map[string][]string{"example.com": {"v=spf1 ip4:192.168.1.1 -all"}},
			expectedPass: true,
		},
		{
			name:         "Exact IPv4 match (+ qualifier)",
			ip:           "192.168.1.1",
			domain:       "example.com",
			mockRecords:  map[string][]string{"example.com": {"v=spf1 +ip4:192.168.1.1 -all"}},
			expectedPass: true,
		},
		{
			name:         "IPv4 CIDR match",
			ip:           "192.168.1.5",
			domain:       "example.com",
			mockRecords:  map[string][]string{"example.com": {"v=spf1 ip4:192.168.1.0/24 -all"}},
			expectedPass: true,
		},
		{
			name:         "IPv4 CIDR no match",
			ip:           "192.168.2.5",
			domain:       "example.com",
			mockRecords:  map[string][]string{"example.com": {"v=spf1 ip4:192.168.1.0/24 -all"}},
			expectedPass: false,
		},
		{
			name:         "Exact IPv6 match",
			ip:           "2001:0db8::1",
			domain:       "example.com",
			mockRecords:  map[string][]string{"example.com": {"v=spf1 ip6:2001:0db8::1 -all"}},
			expectedPass: true,
		},
		{
			name:         "IPv6 CIDR match",
			ip:           "2001:0db8::f00d",
			domain:       "example.com",
			mockRecords:  map[string][]string{"example.com": {"v=spf1 ip6:2001:0db8::/32 -all"}},
			expectedPass: true,
		},
		{
			name:         "IPv6 CIDR no match",
			ip:           "2001:0db9::f00d",
			domain:       "example.com",
			mockRecords:  map[string][]string{"example.com": {"v=spf1 ip6:2001:0db8::/32 -all"}},
			expectedPass: false,
		},
		{
			name:         "No SPF record, neutral",
			ip:           "1.1.1.1",
			domain:       "example.com",
			mockRecords:  map[string][]string{"example.com": {"someothertxtrecord"}},
			expectedPass: true,
		},
		{
			name:         "SPF record but no match, -all",
			ip:           "1.1.1.1",
			domain:       "example.com",
			mockRecords:  map[string][]string{"example.com": {"v=spf1 ip4:2.2.2.2 -all"}},
			expectedPass: false,
		},
		{
			name:         "SPF record but no match, ~all",
			ip:           "1.1.1.1",
			domain:       "example.com",
			mockRecords:  map[string][]string{"example.com": {"v=spf1 ip4:2.2.2.2 ~all"}},
			expectedPass: false, // Softfail treated as fail for DMARC context
		},
		{
			name:         "SPF record but no match, ?all",
			ip:           "1.1.1.1",
			domain:       "example.com",
			mockRecords:  map[string][]string{"example.com": {"v=spf1 ip4:2.2.2.2 ?all"}},
			expectedPass: true, // Neutral treated as pass for DMARC context
		},
		{
			name:         "Include mechanism - pass",
			ip:           "10.0.0.1",
			domain:       "example.com",
			mockRecords: map[string][]string{
				"example.com":     {"v=spf1 include:sub.example.com -all"},
				"sub.example.com": {"v=spf1 ip4:10.0.0.0/24 -all"},
			},
			expectedPass: true,
		},
		{
			name:         "Include mechanism - fail from sub-domain",
			ip:           "10.0.1.1",
			domain:       "example.com",
			mockRecords: map[string][]string{
				"example.com":     {"v=spf1 include:sub.example.com -all"},
				"sub.example.com": {"v=spf1 ip4:10.0.0.0/24 -all"},
			},
			expectedPass: false,
		},
		{
			name:         "Redirect mechanism - pass",
			ip:           "10.0.0.1",
			domain:       "example.com",
			mockRecords: map[string][]string{
				"example.com":     {"v=spf1 redirect=sub.example.com"},
				"sub.example.com": {"v=spf1 ip4:10.0.0.0/24 -all"},
			},
			expectedPass: true,
		},
		{
			name:         "Redirect mechanism - fail from sub-domain",
			ip:           "10.0.1.1",
			domain:       "example.com",
			mockRecords: map[string][]string{
				"example.com":     {"v=spf1 redirect=sub.example.com"},
				"sub.example.com": {"v=spf1 ip4:10.0.0.0/24 -all"},
			},
			expectedPass: false,
		},
		{
			name:         "Complex record with multiple mechanisms - match first",
			ip:           "192.168.1.10",
			domain:       "example.com",
			mockRecords:  map[string][]string{"example.com": {"v=spf1 ip4:192.168.1.0/24 ip4:10.0.0.0/8 -all"}},
			expectedPass: true,
		},
		{
			name:         "Complex record with multiple mechanisms - match second",
			ip:           "10.0.0.10",
			domain:       "example.com",
			mockRecords:  map[string][]string{"example.com": {"v=spf1 ip4:192.168.1.0/24 ip4:10.0.0.0/8 -all"}},
			expectedPass: true,
		},
		{
			name:         "Complex record with include and all",
			ip:           "172.16.0.5",
			domain:       "example.com",
			mockRecords: map[string][]string{
				"example.com":     {"v=spf1 ip4:192.168.1.0/24 include:other.com ~all"},
				"other.com":       {"v=spf1 ip4:172.16.0.0/16 -all"},
				"another.com":     {"v=spf1 ip4:1.2.3.4 -all"},
			},
			expectedPass: true,
		},
		{
			name:         "Complex record with include, no match, then ~all",
			ip:           "1.1.1.1",
			domain:       "example.com",
			mockRecords: map[string][]string{
				"example.com":     {"v=spf1 ip4:192.168.1.0/24 include:other.com ~all"},
				"other.com":       {"v=spf1 ip4:172.16.0.0/16 -all"},
			},
			expectedPass: false, // ~all
		},
		{
			name:         "DNS lookup error for main domain",
			ip:           "1.1.1.1",
			domain:       "example.com",
			mockRecords:  nil,
			mockErr:      errors.New("lookup example.com: server failed"),
			expectedPass: true, // Treated as neutral/pass on lookup error
		},
		{
			name:         "DNS lookup error for included domain",
			ip:           "1.1.1.1",
			domain:       "example.com",
			mockRecords: map[string][]string{
				"example.com": {"v=spf1 include:nonexistent.com -all"},
			},
			mockErr: errors.New("lookup nonexistent.com: no such host"), // Simulate error for include
			expectedPass: false, // Error in include makes primary fail if -all is present
		},
		{
			name:         "Max recursion depth reached for include",
			ip:           "1.1.1.1",
			domain:       "example.com",
			mockRecords: map[string][]string{
				"example.com":     {"v=spf1 include:sub1.example.com -all"},
				"sub1.example.com": {"v=spf1 include:sub2.example.com -all"},
				"sub2.example.com": {"v=spf1 include:sub3.example.com -all"},
				"sub3.example.com": {"v=spf1 include:sub4.example.com -all"},
				"sub4.example.com": {"v=spf1 include:sub5.example.com -all"},
				"sub5.example.com": {"v=spf1 include:sub6.example.com -all"},
				"sub6.example.com": {"v=spf1 include:sub7.example.com -all"},
				"sub7.example.com": {"v=spf1 include:sub8.example.com -all"},
				"sub8.example.com": {"v=spf1 include:sub9.example.com -all"},
				"sub9.example.com": {"v=spf1 include:sub10.example.com -all"},
				"sub10.example.com": {"v=spf1 include:sub11.example.com -all"}, // This will trigger max depth
				"sub11.example.com": {"v=spf1 ip4:1.1.1.1 -all"},
			},
			expectedPass: false,
		},
		{
			name:         "Invalid IP provided",
			ip:           "invalid-ip",
			domain:       "example.com",
			mockRecords:  map[string][]string{"example.com": {"v=spf1 ip4:1.1.1.1 -all"}},
			expectedPass: false,
		},
		{
			name:         "Multiple SPF records, only one with v=spf1",
			ip:           "192.168.1.1",
			domain:       "example.com",
			mockRecords:  map[string][]string{"example.com": {"v=spf1 ip4:192.168.1.1 -all", "v=spf1 ip4:1.2.3.4 -all"}},
			expectedPass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupMockLookupTXT(t, tt.mockRecords, tt.mockErr)
			defer teardownMockLookupTXT()

			pass, err := VerifySPF(tt.ip, tt.domain)

			if err != nil && tt.mockErr == nil {
				t.Errorf("VerifySPF() unexpected error = %v", err)
			}
			if pass != tt.expectedPass {
				t.Errorf("VerifySPF() got = %v, want %v", pass, tt.expectedPass)
			}
		})
	}
}

func TestVerifyDMARC(t *testing.T) {
	tests := []struct {
		name           string
		domain         string
		spfPass        bool
		dkimPass       bool
		mockRecords    map[string][]string
		mockErr        error
		expectedPass   bool
		expectedPolicy string
	}{
		{
			name:         "DMARC record with p=reject, SPF pass, DKIM fail",
			domain:       "example.com",
			spfPass:      true,
			dkimPass:     false,
			mockRecords:  map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject; rua=mailto:a@example.com"}},
			expectedPass: true,
			expectedPolicy: "reject",
		},
		{
			name:         "DMARC record with p=reject, SPF fail, DKIM pass",
			domain:       "example.com",
			spfPass:      false,
			dkimPass:     true,
			mockRecords:  map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject; rua=mailto:a@example.com"}},
			expectedPass: true,
			expectedPolicy: "reject",
		},
		{
			name:         "DMARC record with p=quarantine, SPF fail, DKIM fail",
			domain:       "example.com",
			spfPass:      false,
			dkimPass:     false,
			mockRecords:  map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=quarantine"}},
			expectedPass: false,
			expectedPolicy: "quarantine",
		},
		{
			name:         "No DMARC record, SPF fail, DKIM pass",
			domain:       "example.com",
			spfPass:      false,
			dkimPass:     true,
			mockRecords:  nil, // Simulate no _dmarc TXT record
			mockErr:      errors.New("host not found"),
			expectedPass: true,
			expectedPolicy: "none",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupMockLookupTXT(t, tt.mockRecords, tt.mockErr)
			defer teardownMockLookupTXT()

			pass, policy, err := VerifyDMARC(tt.domain, tt.spfPass, tt.dkimPass)

			if err != nil && tt.mockErr == nil {
				t.Errorf("VerifyDMARC() unexpected error = %v", err)
			}

			if pass != tt.expectedPass {
				t.Errorf("VerifyDMARC() got pass = %v, want %v", pass, tt.expectedPass)
			}
			if policy != tt.expectedPolicy {
				t.Errorf("VerifyDMARC() got policy = %v, want %v", policy, tt.expectedPolicy)
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