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

func verifySPFRecursive(ip, domain string, depth int) (bool, error) {
	if depth > 10 {
		log.Printf("[SPF] Max recursion depth reached for domain: %s", domain)
		return false, nil // Limit recursion to avoid infinite loops
	}

	log.Printf("[SPF] Looking up TXT records for: %s (depth: %d)", domain, depth)
	txts, err := net.LookupTXT(domain)
	if err != nil {
		log.Printf("[SPF] Lookup failed for %s: %v. Treating as neutral/pass.", domain, err)
		return true, nil // Treat lookup errors as neutral/pass for simplicity
	}

	spfRecordFound := false
	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=spf1") {
			log.Printf("[SPF] Found record: %s", txt)
			spfRecordFound = true
			// Simplified check: look for the IP and handle failure suffixes.
			if strings.Contains(txt, "ip4:"+ip) || strings.Contains(txt, "ip6:"+ip) {
				log.Printf("[SPF] Match found for IP %s in record", ip)
				return true, nil
			}

			// Handle redirect= modifier.
			if strings.Contains(txt, "redirect=") {
				parts := strings.Fields(txt)
				for _, part := range parts {
					if strings.HasPrefix(part, "redirect=") {
						redirectDomain := strings.TrimPrefix(part, "redirect=")
						log.Printf("[SPF] Following redirect to: %s", redirectDomain)
						return verifySPFRecursive(ip, redirectDomain, depth+1)
					}
				}
			}

			// If the record has -all (hard fail) or ~all (soft fail) and we haven't matched,
			// we should treat it as a failure for the purpose of strict DMARC.
			if strings.Contains(txt, "-all") || strings.Contains(txt, "~all") {
				log.Printf("[SPF] No match found and record contains fail suffix (-all/~all)")
				return false, nil
			}
		}
	}

	// If no v=spf1 record was found, it's neutral (pass).
	// If a record was found but no match/fail/redirect mechanism was hit, we treat it as fail.
	result := !spfRecordFound
	log.Printf("[SPF] Finished for %s. Record found: %v, Result (pass): %v", domain, spfRecordFound, result)
	return result, nil
}

// VerifyDMARC performs a basic DMARC check based on the SPF result.
func VerifyDMARC(domain string, spfPass bool) (bool, string, error) {
	log.Printf("[DMARC] Checking domain: %s (SPF Pass: %v)", domain, spfPass)
	txts, err := net.LookupTXT("_dmarc." + domain)
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
