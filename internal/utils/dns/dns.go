package dns

import (
	"log"
	"net"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
)

// VerifySPF checks if the provided IP is authorized to send mail for the given domain.
// This is a simplified implementation of SPF validation.
func VerifySPF(ip, domain string) (bool, error) {
	log.Printf("[SPF] Starting verification for IP: %s, Domain: %s", ip, domain)
	if ip == "" {
		log.Printf("[SPF] Empty IP address provided. Treating as neutral/pass.")
		return true, nil
	}
	return verifySPFRecursive(ip, domain, 0)
}

var LookupTXTFunc = net.LookupTXT
var LookupMXFunc = net.LookupMX
var LookupIPFunc = net.LookupIP
var LookupAddrFunc = net.LookupAddr

func verifySPFRecursive(ipStr, domain string, depth int) (bool, error) {
	if depth > 10 {
		log.Printf("[SPF] Max recursion depth reached for domain: %s", domain)
		return false, nil // Limit recursion to avoid infinite loops
	}

	incomingIP := net.ParseIP(ipStr)
	if incomingIP == nil {
		log.Printf("[SPF] Invalid IP address provided: %s", ipStr)
		return false, nil
	}

	log.Printf("[SPF] Looking up TXT records for: %s (depth: %d)", domain, depth)
	txts, err := LookupTXTFunc(domain)
	if err != nil {
		log.Printf("[SPF] Lookup failed for %s (depth: %d): %v.", domain, depth, err)
		// If it's a top-level domain and lookup fails, it's neutral/pass.
		// If it's an include (depth > 0) and lookup fails, it's a fail.
		if depth == 0 {
			log.Print("[SPF] Treating top-level domain lookup failure as neutral/pass.")
			return true, nil // Treat top-level lookup errors as neutral/pass for simplicity
		} else {
			log.Print("[SPF] Treating include domain lookup failure as fail.")
			return false, nil // Treat include lookup errors as fail
		}
	}
	log.Printf("[SPF] Found TXT records: %v", txts)

	spfRecordFound := false

	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=spf1") {
			log.Printf("[SPF] Found record: %s", txt)
			spfRecordFound = true
			mechanisms := strings.Fields(txt[len("v=spf1"):])

			var hasAll bool
			var allQualifier string

			for _, mechanism := range mechanisms {
				qualifier := "+" // Default qualifier is '+'
				mechValue := mechanism

				if len(mechanism) > 0 {
					switch mechanism[0] {
					case '+', '-', '~', '?':
						qualifier = string(mechanism[0])
						mechValue = mechanism[1:]
					}
				}

				if strings.HasPrefix(mechValue, "ip4:") {
					ipEntry := strings.TrimPrefix(mechValue, "ip4:")
					if checkIPMechanism(incomingIP, ipEntry, net.IPv4len) {
						log.Printf("[SPF] IP %s matched ip4 mechanism: %s (Qualifier: %s)", ipStr, mechValue, qualifier)
						return evaluateQualifier(qualifier), nil
					}
				} else if strings.HasPrefix(mechValue, "ip6:") {
					ipEntry := strings.TrimPrefix(mechValue, "ip6:")
					if checkIPMechanism(incomingIP, ipEntry, net.IPv6len) {
						log.Printf("[SPF] IP %s matched ip6 mechanism: %s (Qualifier: %s)", ipStr, mechValue, qualifier)
						return evaluateQualifier(qualifier), nil
					}
				} else if mechValue == "a" || strings.HasPrefix(mechValue, "a:") || strings.HasPrefix(mechValue, "a/") {
					aDomain := domain
					// Check for explicit domain a:example.com
					if strings.HasPrefix(mechValue, "a:") {
						aDomain = strings.Split(strings.TrimPrefix(mechValue, "a:"), "/")[0]
					}

					ips, err := LookupIPFunc(aDomain)
					if err == nil {
						for _, ip := range ips {
							if ip.Equal(incomingIP) {
								log.Printf("[SPF] IP %s matched a mechanism: %s", ipStr, mechValue)
								return evaluateQualifier(qualifier), nil
							}
						}
					}
				} else if mechValue == "mx" || strings.HasPrefix(mechValue, "mx:") || strings.HasPrefix(mechValue, "mx/") {
					mxDomain := domain
					if strings.HasPrefix(mechValue, "mx:") {
						mxDomain = strings.Split(strings.TrimPrefix(mechValue, "mx:"), "/")[0]
					}

					mxs, err := LookupMXFunc(mxDomain)
					if err == nil {
						for _, mx := range mxs {
							ips, err := LookupIPFunc(mx.Host)
							if err == nil {
								for _, ip := range ips {
									if ip.Equal(incomingIP) {
										log.Printf("[SPF] IP %s matched mx mechanism: %s (via %s)", ipStr, mechValue, mx.Host)
										return evaluateQualifier(qualifier), nil
									}
								}
							}
						}
					}
				} else if mechValue == "ptr" || strings.HasPrefix(mechValue, "ptr:") {
					ptrDomain := domain
					if strings.HasPrefix(mechValue, "ptr:") {
						ptrDomain = strings.TrimPrefix(mechValue, "ptr:")
					}

					names, err := LookupAddrFunc(ipStr)
					if err == nil {
						for _, name := range names {
							name = strings.TrimSuffix(name, ".")
							if strings.HasSuffix(name, ptrDomain) {
								ips, err := LookupIPFunc(name)
								if err == nil {
									for _, ip := range ips {
										if ip.Equal(incomingIP) {
											log.Printf("[SPF] IP %s matched ptr mechanism: %s (via %s)", ipStr, mechValue, name)
											return evaluateQualifier(qualifier), nil
										}
									}
								}
							}
						}
					}
				} else if strings.HasPrefix(mechValue, "exists:") {
					existsDomain := strings.TrimPrefix(mechValue, "exists:")
					ips, err := LookupIPFunc(existsDomain)
					if err == nil && len(ips) > 0 {
						log.Printf("[SPF] IP %s matched exists mechanism: %s", ipStr, mechValue)
						return evaluateQualifier(qualifier), nil
					}
				} else if strings.HasPrefix(mechValue, "include:") {
					includeDomain := strings.TrimPrefix(mechValue, "include:")
					log.Printf("[SPF] Following include to: %s (depth: %d)", includeDomain, depth+1)
					includePass, err := verifySPFRecursive(ipStr, includeDomain, depth+1)
					if err != nil {
						log.Printf("[SPF] Error during include check for %s: %v", includeDomain, err)
						// Treat include lookup error as a fail
						return false, nil
					}
					if includePass {
						log.Printf("[SPF] Include mechanism for %s passed.", includeDomain)
						return evaluateQualifier(qualifier), nil
					}
				} else if strings.HasPrefix(mechValue, "redirect=") {
					redirectDomain := strings.TrimPrefix(mechValue, "redirect=")
					log.Printf("[SPF] Following redirect to: %s (depth: %d)", redirectDomain, depth+1)
					return verifySPFRecursive(ipStr, redirectDomain, depth+1)
				} else if mechValue == "all" {
					hasAll = true
					allQualifier = qualifier
				}
			}

			if hasAll {
				log.Printf("[SPF] No specific mechanism matched. Evaluating all mechanism (Qualifier: %s)", allQualifier)
				return evaluateQualifier(allQualifier), nil
			}
		}
	}

	// If no v=spf1 record was found, or none of them matched, it's neutral (pass).
	result := true
	log.Printf("[SPF] Finished for %s. SPF record found: %v, Result (pass): %v", domain, spfRecordFound, result)
	return result, nil
}

// checkIPMechanism parses an IP entry (e.g., "192.168.1.1/24" or "192.168.1.1")
// and checks if the incomingIP matches it.
func checkIPMechanism(incomingIP net.IP, ipEntry string, ipLen int) bool {
	// Try parsing as CIDR first
	if _, ipnet, err := net.ParseCIDR(ipEntry); err == nil {
		return ipnet.Contains(incomingIP)
	}

	// Try parsing as single IP
	if ip := net.ParseIP(ipEntry); ip != nil {
		if ipLen == net.IPv4len && incomingIP.To4() != nil && ip.Equal(incomingIP) {
			return true
		} else if ipLen == net.IPv6len && incomingIP.To16() != nil && ip.Equal(incomingIP) {
			return true
		}
	}
	return false
}

// evaluateQualifier returns true for '+' and '?' qualifiers (pass/neutral), and false for '-' and '~' (fail/softfail).
func evaluateQualifier(qualifier string) bool {
	switch qualifier {
	case "-", "~":
		return false
	case "+", "?": // Neutral acts as pass for simplified DMARC flow
		return true
	default: // Default is '+'
		return true
	}
}

// VerifyDMARC performs a basic DMARC check based on the SPF and DKIM results.
func VerifyDMARC(domain string, spfPass, dkimPass bool) (bool, string, error) {
	log.Printf("[DMARC] Checking domain: %s (SPF Pass: %v, DKIM Pass: %v)", domain, spfPass, dkimPass)
	txts, err := LookupTXTFunc("_dmarc." + domain)
	if err != nil {
		log.Printf("[DMARC] No record found for _dmarc.%s. Returning combined SPF/DKIM result.", domain)
		return spfPass || dkimPass, "none", nil // No DMARC record found, return actual auth status
	}

	policy := "none"
	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=DMARC1") {
			log.Printf("[DMARC] Found record: %s", txt)
			if strings.Contains(txt, "p=reject") {
				policy = "reject"
			} else if strings.Contains(txt, "p=quarantine") {
				policy = "quarantine"
			}
			break
		}
	}

	log.Printf("[DMARC] Policy for %s is %s. SPF Pass: %v, DKIM Pass: %v", domain, policy, spfPass, dkimPass)
	// DMARC passes if either SPF or DKIM passes (simplified: no alignment check yet)
	return spfPass || dkimPass, policy, nil
}

// LookupMX returns the hostnames of the MX records for the given domain, sorted by preference.
func LookupMX(domain string) ([]string, error) {
	log.Printf("[DNS] Looking up MX records for: %s", domain)
	mxRecords, err := LookupMXFunc(domain)
	if err != nil {
		return nil, err
	}

	hosts := make([]string, len(mxRecords))
	for i, mx := range mxRecords {
		hosts[i] = strings.TrimSuffix(mx.Host, ".")
	}
	return hosts, nil
}

// VerifyDKIM verifies the DKIM signatures of the provided email body.
func VerifyDKIM(body string) (bool, error) {
	log.Printf("[DKIM] Starting verification")
	reader := strings.NewReader(body)
	verifications, err := dkim.Verify(reader)
	if err != nil {
		log.Printf("[DKIM] Verification failed to initialize: %v", err)
		return false, err
	}

	for _, v := range verifications {
		if v.Err == nil {
			log.Printf("[DKIM] Signature verified for domain: %s", v.Domain)
			return true, nil
		}
		log.Printf("[DKIM] Signature failed for domain %s: %v", v.Domain, v.Err)
	}

	if len(verifications) == 0 {
		log.Printf("[DKIM] No signatures found")
	}

	return false, nil
}
