package dns

import (
	"log"
	"net"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
)

// SPFResult represents the result of an SPF check as defined in RFC 7208.
type SPFResult string

const (
	SPFPass      SPFResult = "Pass"
	SPFFail      SPFResult = "Fail"
	SPFSoftFail  SPFResult = "SoftFail"
	SPFNeutral   SPFResult = "Neutral"
	SPFNone      SPFResult = "None"
	SPFTempError SPFResult = "TempError"
	SPFPermError SPFResult = "PermError"
)

// VerifySPF checks if the provided IP is authorized to send mail for the given domain.
// This is a simplified implementation of SPF validation.
func VerifySPF(ip, domain string) (SPFResult, error) {
	log.Printf("[SPF] Starting verification for IP: %s, Domain: %s", ip, domain)
	if ip == "" {
		log.Printf("[SPF] Empty IP address provided. Returning Neutral.")
		return SPFNeutral, nil
	}
	return verifySPFRecursive(ip, domain, 0)
}

var LookupTXTFunc = net.LookupTXT
var LookupMXFunc = net.LookupMX
var LookupIPFunc = net.LookupIP
var LookupAddrFunc = net.LookupAddr

func verifySPFRecursive(ipStr, domain string, depth int) (SPFResult, error) {
	if depth > 10 {
		log.Printf("[SPF] Max recursion depth reached for domain: %s", domain)
		return SPFPermError, nil // Limit recursion to avoid infinite loops
	}

	incomingIP := net.ParseIP(ipStr)
	if incomingIP == nil {
		log.Printf("[SPF] Invalid IP address provided: %s", ipStr)
		return SPFPermError, nil
	}

	log.Printf("[SPF] Looking up TXT records for: %s (depth: %d)", domain, depth)
	txts, err := LookupTXTFunc(domain)
	if err != nil {
		log.Printf("[SPF] Lookup failed for %s (depth: %d): %v.", domain, depth, err)
		// RFC 7208: If the DNS lookup returns a server failure (RCODE 2) or some other error condition,
		// the result is "temperror". If the DNS lookup returns a name error (RCODE 3), the result is "none".
		// We use a simplified check here.
		if strings.Contains(err.Error(), "no such host") {
			return SPFNone, nil
		}
		return SPFTempError, err
	}
	log.Printf("[SPF] Found TXT records: %v", txts)

	var spfRecords []string
	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=spf1") {
			spfRecords = append(spfRecords, txt)
		}
	}

	if len(spfRecords) == 0 {
		return SPFNone, nil
	}
	if len(spfRecords) > 1 {
		log.Printf("[SPF] Multiple SPF records found for %s", domain)
		return SPFPermError, nil
	}

	txt := spfRecords[0]
	log.Printf("[SPF] Found record: %s", txt)
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
						return qualifierToResult(qualifier), nil
					}
				} else if strings.HasPrefix(mechValue, "ip6:") {
					ipEntry := strings.TrimPrefix(mechValue, "ip6:")
					if checkIPMechanism(incomingIP, ipEntry, net.IPv6len) {
						log.Printf("[SPF] IP %s matched ip6 mechanism: %s (Qualifier: %s)", ipStr, mechValue, qualifier)
						return qualifierToResult(qualifier), nil
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
								return qualifierToResult(qualifier), nil
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
										return qualifierToResult(qualifier), nil
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
											return qualifierToResult(qualifier), nil
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
						return qualifierToResult(qualifier), nil
					}
				} else if strings.HasPrefix(mechValue, "include:") {
					includeDomain := strings.TrimPrefix(mechValue, "include:")
					log.Printf("[SPF] Following include to: %s (depth: %d)", includeDomain, depth+1)
					includeResult, err := verifySPFRecursive(ipStr, includeDomain, depth+1)
					if err != nil {
						log.Printf("[SPF] Error during include check for %s: %v", includeDomain, err)
						return SPFTempError, err
					}
					switch includeResult {
					case SPFPass:
						log.Printf("[SPF] Include mechanism for %s passed.", includeDomain)
						return qualifierToResult(qualifier), nil
					case SPFFail, SPFSoftFail, SPFNeutral:
						// No match, continue
					case SPFNone, SPFPermError:
						return SPFPermError, nil
					case SPFTempError:
						return SPFTempError, nil
					}
				} else if strings.HasPrefix(mechValue, "redirect=") {
					redirectDomain := strings.TrimPrefix(mechValue, "redirect=")
					log.Printf("[SPF] Following redirect to: %s (depth: %d)", redirectDomain, depth+1)
					redirectResult, err := verifySPFRecursive(ipStr, redirectDomain, depth+1)
					if err != nil {
						return SPFTempError, err
					}
					if redirectResult == SPFNone {
						return SPFPermError, nil
					}
					return redirectResult, nil
				} else if mechValue == "all" {
					hasAll = true
					allQualifier = qualifier
				}
			}

			if hasAll {
				log.Printf("[SPF] No specific mechanism matched. Evaluating all mechanism (Qualifier: %s)", allQualifier)
				return qualifierToResult(allQualifier), nil
			}

	// If no match was found, and no 'all' mechanism, it's Neutral.
	log.Printf("[SPF] Finished for %s. No match found. Result: %s", domain, SPFNeutral)
	return SPFNeutral, nil
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

// qualifierToResult returns the SPFResult corresponding to the given qualifier.
func qualifierToResult(qualifier string) SPFResult {
	switch qualifier {
	case "+":
		return SPFPass
	case "-":
		return SPFFail
	case "~":
		return SPFSoftFail
	case "?":
		return SPFNeutral
	default: // Default is '+'
		return SPFPass
	}
}

// VerifyDMARC performs a basic DMARC check based on the SPF and DKIM results.
func VerifyDMARC(domain string, spfResult SPFResult, dkimPass bool) (bool, string, error) {
	log.Printf("[DMARC] Checking domain: %s (SPF Result: %v, DKIM Pass: %v)", domain, spfResult, dkimPass)
	txts, err := LookupTXTFunc("_dmarc." + domain)
	spfPass := (spfResult == SPFPass)
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
