package dns

import (
	"log"
	"net"
	"strings"
)

// VerifySPF checks if the provided IP is authorized to send mail for the given domain.
// This is a simplified implementation of SPF validation.
func VerifySPF(ip, domain string) (bool, error) {
	log.Printf("[SPF] Starting verification for IP: %s, Domain: %s", ip, domain)
	return verifySPFRecursive(ip, domain, 0)
}

var lookupTXTFunc = net.LookupTXT
var lookupMXFunc = net.LookupMX

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
	txts, err := lookupTXTFunc(domain)
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
	var finalAllQualifier string // To store the qualifier for 'all' mechanism if found

	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=spf1") {
			log.Printf("[SPF] Found record: %s", txt)
			spfRecordFound = true
			mechanisms := strings.Fields(txt[len("v=spf1"):])

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
				} else if strings.HasPrefix(mechValue, "include:") {
					includeDomain := strings.TrimPrefix(mechValue, "include:")
					log.Printf("[SPF] Following include to: %s (depth: %d)", includeDomain, depth+1)
					includePass, err := verifySPFRecursive(ipStr, includeDomain, depth+1)
					if err != nil {
						log.Printf("[SPF] Error during include check for %s: %v", includeDomain, err)
						// If an include mechanism's DNS lookup fails, it typically results in a 'fail' or 'permerror'.
						// For simplicity, we treat it as a fail unless overridden by a '+' or '?' qualifier.
						return false, nil // Treat include lookup error as a fail
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
					finalAllQualifier = qualifier
				}
			}
			// If we reached here, no specific mechanism caused a PASS or FAIL.
			// Now evaluate the 'all' mechanism if it was present.
			if finalAllQualifier != "" {
				log.Printf("[SPF] No specific mechanism matched. Evaluating 'all' mechanism with qualifier: %s", finalAllQualifier)
				return evaluateQualifier(finalAllQualifier), nil
			} else {
				// If no 'all' mechanism and no other match, it's neutral (pass)
				log.Printf("[SPF] No specific mechanism matched and no 'all' mechanism. Treating as neutral/pass.")
				return true, nil
			}
		}
	}

	// If no v=spf1 record was found, it's neutral (pass).
	// If a record was found but no match/fail/redirect mechanism was hit and no 'all' mechanism was present, we treat it as neutral.
	result := !spfRecordFound
	log.Printf("[SPF] Finished for %s. SPF record found: %v, Result (pass): %v", domain, spfRecordFound, result)
	return result, nil
}

// checkIPMechanism parses an IP entry (e.g., "192.168.1.1/24" or "192.168.1.1")
// and checks if the incomingIP matches it.
func checkIPMechanism(incomingIP net.IP, ipEntry string, ipLen int) bool {
	if _, ipnet, err := net.ParseCIDR(ipEntry); err == nil {
		if ipnet.Contains(incomingIP) {
			return true
		}
	} else if ip := net.ParseIP(ipEntry); ip != nil {
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

// VerifyDMARC performs a basic DMARC check based on the SPF result.
func VerifyDMARC(domain string, spfPass bool) (bool, string, error) {
	log.Printf("[DMARC] Checking domain: %s (SPF Pass: %v)", domain, spfPass)
	txts, err := lookupTXTFunc("_dmarc." + domain)
	if err != nil {
		log.Printf("[DMARC] No record found for _dmarc.%s. Returning SPF result.", domain)
		return spfPass, "none", nil // No DMARC record found, return actual auth status
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

	log.Printf("[DMARC] Policy for %s is %s. SPF Pass: %v", domain, policy, spfPass)
	// DMARC passes if SPF passes (simplified: no DKIM/alignment check yet)
	return spfPass, policy, nil
}

// LookupMX returns the hostnames of the MX records for the given domain, sorted by preference.
func LookupMX(domain string) ([]string, error) {
	log.Printf("[DNS] Looking up MX records for: %s", domain)
	mxRecords, err := lookupMXFunc(domain)
	if err != nil {
		return nil, err
	}

	hosts := make([]string, len(mxRecords))
	for i, mx := range mxRecords {
		hosts[i] = strings.TrimSuffix(mx.Host, ".")
	}
	return hosts, nil
}
