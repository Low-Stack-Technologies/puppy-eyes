package dns

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

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

type SPFMacroContext struct {
	Sender string
	Helo   string
	Now    time.Time
}

// VerifySPF checks if the provided IP is authorized to send mail for the given domain.
// This is a simplified implementation of SPF validation.
func VerifySPF(ip, domain string, ctx SPFMacroContext) (SPFResult, error) {
	log.Printf("[SPF] Starting verification for IP: %s, Domain: %s, Sender: %s, Helo: %s", ip, domain, ctx.Sender, ctx.Helo)
	if ip == "" {
		log.Printf("[SPF] Empty IP address provided. Returning Neutral.")
		return SPFNeutral, nil
	}
	if ctx.Now.IsZero() {
		ctx.Now = time.Now().UTC()
	}
	return verifySPFRecursive(ip, domain, ctx, 0)
}

var LookupTXTFunc = net.LookupTXT
var LookupMXFunc = net.LookupMX
var LookupIPFunc = net.LookupIP
var LookupAddrFunc = net.LookupAddr

type macroContext struct {
	ipStr  string
	ip     net.IP
	domain string
	sender string
	helo   string
	now    time.Time

	ptrValidatedLoaded bool
	ptrValidated       string
	ptrRawLoaded       bool
	ptrRaw             string
}

func verifySPFRecursive(ipStr, domain string, spfCtx SPFMacroContext, depth int) (SPFResult, error) {
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
	ctx := macroContext{
		ipStr:  ipStr,
		ip:     incomingIP,
		domain: domain,
		sender: spfCtx.Sender,
		helo:   spfCtx.Helo,
		now:    spfCtx.Now,
	}

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

			if strings.Contains(aDomain, "%") {
				expanded, err := expandSPFMacros(aDomain, &ctx)
				if err != nil || !isValidDomainName(expanded) {
					log.Printf("[SPF] Macro expansion failed for a mechanism domain %s: %v", aDomain, err)
					return SPFPermError, nil
				}
				aDomain = expanded
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

			if strings.Contains(mxDomain, "%") {
				expanded, err := expandSPFMacros(mxDomain, &ctx)
				if err != nil || !isValidDomainName(expanded) {
					log.Printf("[SPF] Macro expansion failed for mx mechanism domain %s: %v", mxDomain, err)
					return SPFPermError, nil
				}
				mxDomain = expanded
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

			if strings.Contains(ptrDomain, "%") {
				expanded, err := expandSPFMacros(ptrDomain, &ctx)
				if err != nil || !isValidDomainName(expanded) {
					log.Printf("[SPF] Macro expansion failed for ptr mechanism domain %s: %v", ptrDomain, err)
					return SPFPermError, nil
				}
				ptrDomain = expanded
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
			if strings.Contains(existsDomain, "%") {
				expanded, err := expandSPFMacros(existsDomain, &ctx)
				if err != nil || !isValidDomainName(expanded) {
					log.Printf("[SPF] Macro expansion failed for exists mechanism domain %s: %v", existsDomain, err)
					return SPFPermError, nil
				}
				existsDomain = expanded
			}
			ips, err := LookupIPFunc(existsDomain)
			if err == nil && len(ips) > 0 {
				log.Printf("[SPF] IP %s matched exists mechanism: %s", ipStr, mechValue)
				return qualifierToResult(qualifier), nil
			}
		} else if strings.HasPrefix(mechValue, "include:") {
			includeDomain := strings.TrimPrefix(mechValue, "include:")
			if strings.Contains(includeDomain, "%") {
				expanded, err := expandSPFMacros(includeDomain, &ctx)
				if err != nil || !isValidDomainName(expanded) {
					log.Printf("[SPF] Macro expansion failed for include mechanism domain %s: %v", includeDomain, err)
					return SPFPermError, nil
				}
				includeDomain = expanded
			}
			log.Printf("[SPF] Following include to: %s (depth: %d)", includeDomain, depth+1)
			includeResult, err := verifySPFRecursive(ipStr, includeDomain, spfCtx, depth+1)
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
			if strings.Contains(redirectDomain, "%") {
				expanded, err := expandSPFMacros(redirectDomain, &ctx)
				if err != nil || !isValidDomainName(expanded) {
					log.Printf("[SPF] Macro expansion failed for redirect domain %s: %v", redirectDomain, err)
					return SPFPermError, nil
				}
				redirectDomain = expanded
			}
			log.Printf("[SPF] Following redirect to: %s (depth: %d)", redirectDomain, depth+1)
			redirectResult, err := verifySPFRecursive(ipStr, redirectDomain, spfCtx, depth+1)
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

func expandSPFMacros(input string, ctx *macroContext) (string, error) {
	var b strings.Builder
	for i := 0; i < len(input); {
		if input[i] != '%' {
			b.WriteByte(input[i])
			i++
			continue
		}
		if i+1 >= len(input) {
			return "", errors.New("unterminated macro")
		}
		switch input[i+1] {
		case '%':
			b.WriteByte('%')
			i += 2
		case '_':
			b.WriteByte(' ')
			i += 2
		case '-':
			b.WriteString("%20")
			i += 2
		case '{':
			end := strings.IndexByte(input[i+2:], '}')
			if end == -1 {
				return "", errors.New("unterminated macro")
			}
			spec := input[i+2 : i+2+end]
			expanded, err := expandMacroSpec(spec, ctx)
			if err != nil {
				return "", err
			}
			b.WriteString(expanded)
			i += 2 + end + 1
		default:
			return "", fmt.Errorf("invalid macro sequence: %q", input[i:i+2])
		}
	}
	return b.String(), nil
}

func expandMacroSpec(spec string, ctx *macroContext) (string, error) {
	if spec == "" {
		return "", errors.New("empty macro")
	}
	macroLetter := spec[0]
	switch macroLetter {
	case 'i', 'd', 's', 'l', 'o', 'h', 'p', 'r', 't', 'v', 'c':
	default:
		return "", fmt.Errorf("unsupported macro: %c", macroLetter)
	}
	rest := spec[1:]
	num, consumed, err := parseMacroDigits(rest)
	if err != nil {
		return "", err
	}
	rest = rest[consumed:]
	reverse := false
	if len(rest) > 0 && rest[0] == 'r' {
		reverse = true
		rest = rest[1:]
	}
	delims := rest
	if delims == "" {
		delims = defaultMacroDelims(macroLetter)
	}

	value, err := macroValue(macroLetter, ctx)
	if err != nil {
		return "", err
	}
	labels := splitMacroLabels(value, delims)
	if len(labels) == 0 {
		return "", errors.New("macro expansion produced no labels")
	}
	if num > 0 && num < len(labels) {
		labels = labels[len(labels)-num:]
	}
	if reverse {
		for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
			labels[i], labels[j] = labels[j], labels[i]
		}
	}
	return strings.Join(labels, "."), nil
}

func parseMacroDigits(input string) (int, int, error) {
	if input == "" || input[0] < '0' || input[0] > '9' {
		return 0, 0, nil
	}
	i := 0
	for i < len(input) && input[i] >= '0' && input[i] <= '9' {
		i++
	}
	num, err := strconv.Atoi(input[:i])
	if err != nil {
		return 0, 0, err
	}
	return num, i, nil
}

func defaultMacroDelims(letter byte) string {
	switch letter {
	case 'i', 'd', 'v', 'c', 'h', 'p', 'r', 't':
		return "."
	case 's', 'l', 'o':
		return ".-+@"
	default:
		return "."
	}
}

func macroValue(letter byte, ctx *macroContext) (string, error) {
	switch letter {
	case 'i':
		return formatIPMacro(ctx.ip)
	case 'd':
		return ctx.domain, nil
	case 's':
		return ctx.sender, nil
	case 'l':
		local, _, err := splitSender(ctx.sender)
		return local, err
	case 'o':
		_, domain, err := splitSender(ctx.sender)
		return domain, err
	case 'h':
		if ctx.helo == "" {
			return "unknown", nil
		}
		return ctx.helo, nil
	case 'p':
		return ctx.ptrValidatedName(), nil
	case 'r':
		return ctx.ptrRawName(), nil
	case 't':
		return strconv.FormatInt(ctx.now.Unix(), 10), nil
	case 'v':
		if ctx.ip.To4() != nil {
			return "in-addr", nil
		}
		return "ip6", nil
	case 'c':
		return ctx.ip.String(), nil
	default:
		return "", fmt.Errorf("unsupported macro: %c", letter)
	}
}

func splitMacroLabels(value, delims string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		return strings.ContainsRune(delims, r)
	})
}

func formatIPMacro(ip net.IP) (string, error) {
	if ip == nil {
		return "", errors.New("invalid IP")
	}
	if ip4 := ip.To4(); ip4 != nil {
		parts := make([]string, 0, net.IPv4len)
		for _, b := range ip4 {
			parts = append(parts, strconv.Itoa(int(b)))
		}
		return strings.Join(parts, "."), nil
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return "", errors.New("invalid IP")
	}
	hexChars := make([]byte, 0, 32)
	for _, b := range ip16 {
		hexChars = append(hexChars, fmt.Sprintf("%02x", b)...)
	}
	nibbles := make([]string, 0, 32)
	for _, c := range string(hexChars) {
		nibbles = append(nibbles, string(c))
	}
	return strings.Join(nibbles, "."), nil
}

func splitSender(sender string) (string, string, error) {
	if sender == "" {
		return "", "", errors.New("empty sender")
	}
	at := strings.LastIndex(sender, "@")
	if at <= 0 || at == len(sender)-1 {
		return "", "", errors.New("invalid sender")
	}
	return sender[:at], sender[at+1:], nil
}

func (ctx *macroContext) ptrValidatedName() string {
	if ctx.ptrValidatedLoaded {
		return ctx.ptrValidated
	}
	ctx.ptrValidatedLoaded = true
	ctx.ptrValidated = "unknown"

	names, err := LookupAddrFunc(ctx.ipStr)
	if err != nil {
		return ctx.ptrValidated
	}
	for _, name := range names {
		name = strings.TrimSuffix(name, ".")
		ips, err := LookupIPFunc(name)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if ip.Equal(ctx.ip) {
				ctx.ptrValidated = name
				return ctx.ptrValidated
			}
		}
	}
	return ctx.ptrValidated
}

func (ctx *macroContext) ptrRawName() string {
	if ctx.ptrRawLoaded {
		return ctx.ptrRaw
	}
	ctx.ptrRawLoaded = true
	ctx.ptrRaw = "unknown"

	names, err := LookupAddrFunc(ctx.ipStr)
	if err != nil || len(names) == 0 {
		return ctx.ptrRaw
	}
	ctx.ptrRaw = strings.TrimSuffix(names[0], ".")
	return ctx.ptrRaw
}

func isValidDomainName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	if name[len(name)-1] == '.' {
		return false
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' {
				continue
			}
			return false
		}
	}
	return true
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

// VerifyDMARC performs a DMARC check with alignment between header From and SPF/DKIM domains.
func VerifyDMARC(headerFromDomain string, spfResult SPFResult, spfDomain string, dkimDomains []string, sampleKey string) (bool, string, error) {
	headerFromDomain = normalizeDomain(headerFromDomain)
	spfDomain = normalizeDomain(spfDomain)

	log.Printf("[DMARC] Checking domain: %s (SPF Result: %v, SPF Domain: %s, DKIM Domains: %v)", headerFromDomain, spfResult, spfDomain, dkimDomains)

	if headerFromDomain == "" {
		log.Printf("[DMARC] Empty header From domain; DMARC alignment fails.")
		return false, "none", nil
	}

	txts, err := LookupTXTFunc("_dmarc." + headerFromDomain)
	policy := dmarcPolicy{
		p:     "none",
		sp:    "",
		adkim: "r",
		aspf:  "r",
		pct:   100,
	}
	if err != nil {
		log.Printf("[DMARC] No record found for _dmarc.%s. Returning aligned auth result.", headerFromDomain)
		spfAligned, dkimAligned := dmarcAlignment(headerFromDomain, spfResult, spfDomain, dkimDomains, policy)
		return spfAligned || dkimAligned, "none", nil
	}

	parsedPolicy, found := parseDMARCRecord(txts)
	if found {
		policy = parsedPolicy
	}

	spfAligned, dkimAligned := dmarcAlignment(headerFromDomain, spfResult, spfDomain, dkimDomains, policy)
	dmarcPass := spfAligned || dkimAligned

	enforcementPolicy := policy.p
	if !dmarcPass && policy.pct < 100 {
		if !pctSelected(sampleKey, policy.pct) {
			enforcementPolicy = "none"
		}
	}

	log.Printf("[DMARC] Policy for %s is %s. SPF Aligned: %v, DKIM Aligned: %v, pct=%d", headerFromDomain, enforcementPolicy, spfAligned, dkimAligned, policy.pct)
	return dmarcPass, enforcementPolicy, nil
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
// Returns whether any signature passed and the list of passing d= domains.
func VerifyDKIM(body string) (bool, []string, error) {
	log.Printf("[DKIM] Starting verification")
	reader := strings.NewReader(body)
	verifications, err := dkim.Verify(reader)
	if err != nil {
		log.Printf("[DKIM] Verification failed to initialize: %v", err)
		return false, nil, err
	}

	passing := make(map[string]struct{})
	for _, v := range verifications {
		if v.Err == nil {
			domain := normalizeDomain(v.Domain)
			if domain != "" {
				passing[domain] = struct{}{}
			}
			log.Printf("[DKIM] Signature verified for domain: %s", v.Domain)
			continue
		}
		log.Printf("[DKIM] Signature failed for domain %s: %v", v.Domain, v.Err)
	}

	if len(verifications) == 0 {
		log.Printf("[DKIM] No signatures found")
	}

	passingDomains := make([]string, 0, len(passing))
	for domain := range passing {
		passingDomains = append(passingDomains, domain)
	}
	return len(passingDomains) > 0, passingDomains, nil
}

func normalizeDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimSuffix(domain, ".")
	return strings.ToLower(domain)
}

func domainsEqualStrict(a, b string) bool {
	return normalizeDomain(a) == normalizeDomain(b)
}

type dmarcPolicy struct {
	p     string
	sp    string
	adkim string
	aspf  string
	pct   int
}

func parseDMARCRecord(txts []string) (dmarcPolicy, bool) {
	policy := dmarcPolicy{
		p:     "none",
		adkim: "r",
		aspf:  "r",
		pct:   100,
	}
	for _, txt := range txts {
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=dmarc1") {
			continue
		}
		log.Printf("[DMARC] Found record: %s", txt)
		parts := strings.Split(txt, ";")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			kv := strings.SplitN(part, "=", 2)
			if len(kv) != 2 {
				continue
			}
			key := strings.ToLower(strings.TrimSpace(kv[0]))
			value := strings.ToLower(strings.TrimSpace(kv[1]))
			switch key {
			case "p":
				if value == "none" || value == "quarantine" || value == "reject" {
					policy.p = value
				}
			case "sp":
				if value == "none" || value == "quarantine" || value == "reject" {
					policy.sp = value
				}
			case "adkim":
				if value == "r" || value == "s" {
					policy.adkim = value
				}
			case "aspf":
				if value == "r" || value == "s" {
					policy.aspf = value
				}
			case "pct":
				if pct, err := strconv.Atoi(value); err == nil {
					if pct < 0 {
						pct = 0
					} else if pct > 100 {
						pct = 100
					}
					policy.pct = pct
				}
			}
		}
		return policy, true
	}
	return policy, false
}

func dmarcAlignment(headerFromDomain string, spfResult SPFResult, spfDomain string, dkimDomains []string, policy dmarcPolicy) (bool, bool) {
	spfAligned := spfResult == SPFPass && domainsAlign(policy.aspf, headerFromDomain, spfDomain)
	dkimAligned := false
	for _, dkimDomain := range dkimDomains {
		if domainsAlign(policy.adkim, headerFromDomain, dkimDomain) {
			dkimAligned = true
			break
		}
	}
	return spfAligned, dkimAligned
}

func domainsAlign(mode, headerFrom, identity string) bool {
	headerFrom = normalizeDomain(headerFrom)
	identity = normalizeDomain(identity)
	if headerFrom == "" || identity == "" {
		return false
	}
	if mode == "s" {
		return headerFrom == identity
	}
	if headerFrom == identity {
		return true
	}
	return strings.HasSuffix(identity, "."+headerFrom)
}

func pctSelected(sampleKey string, pct int) bool {
	if pct >= 100 {
		return true
	}
	if pct <= 0 {
		return false
	}
	sum := sha256.Sum256([]byte(sampleKey))
	val := binary.BigEndian.Uint32(sum[:4]) % 100
	return int(val) < pct
}
