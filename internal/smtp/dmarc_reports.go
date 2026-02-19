package smtp

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/low-stack-technologies/puppy-eyes/internal/db"
	"github.com/low-stack-technologies/puppy-eyes/internal/utils/dns"
)

type dmarcAggregateKey struct {
	PolicyDomain string
	HeaderFrom   string
	SourceIP     string
	Disposition  string
	SPFAligned   bool
	DKIMAligned  bool
	SPFResult    string
	SPFDomain    string
	DKIMDomains  string
}

func recordDMARCEvent(ctx context.Context, result dns.DMARCResult, headerFromDomain, spfDomain, sourceIP string, spfResult dns.SPFResult, dkimDomains []string) {
	event := db.DMARCEvent{
		CreatedAt:        time.Now().UTC(),
		HeaderFromDomain: headerFromDomain,
		PolicyDomain:     result.PolicyDomain,
		UsedOrgFallback:  result.UsedOrgFallback,
		SourceIP:         sourceIP,
		SPFResult:        string(spfResult),
		SPFDomain:        spfDomain,
		DKIMDomains:      dkimDomains,
		SPFAligned:       result.SPFAligned,
		DKIMAligned:      result.DKIMAligned,
		DMARCPass:        result.Pass,
		Disposition:      result.EnforcementPolicy,
		PolicyP:          result.Policy.P,
		PolicySP:         result.Policy.SP,
		PolicyADKIM:      result.Policy.ADKIM,
		PolicyASPF:       result.Policy.ASPF,
		PolicyPCT:        result.Policy.PCT,
		PolicyRUA:        result.Policy.RUA,
		PolicyRUF:        result.Policy.RUF,
		PolicyFO:         result.Policy.FO,
		PolicyRI:         result.Policy.RI,
	}
	if err := db.InsertDMARCEvent(ctx, event); err != nil {
		log.Printf("Failed to store DMARC event: %v", err)
	}
}

func sendDMARCFailureReport(ctx context.Context, result dns.DMARCResult, headerFromDomain, spfDomain, sourceIP string, spfResult dns.SPFResult, dkimDomains []string, rawMessage string) {
	if len(result.Policy.RUF) == 0 {
		return
	}

	recipients := append([]string(nil), result.Policy.RUF...)
	if len(recipients) == 0 {
		return
	}

	headersOnly := extractHeaderBlock(rawMessage)
	report := buildRUFReport(result, headerFromDomain, spfDomain, sourceIP, spfResult, dkimDomains, headersOnly)
	sender := reportSenderAddress()
	if err := enqueueReportEmail(ctx, sender, recipients, report); err != nil {
		log.Printf("Failed to enqueue DMARC failure report: %v", err)
	}
}

func StartDMARCReporter(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		next := nextUTCMidnight()
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(next)):
			start := next.Add(-24 * time.Hour)
			end := next
			err := sendDailyAggregateReports(ctx, start, end)
			if err != nil {
				log.Printf("Failed to send DMARC aggregate reports: %v", err)
			}
		}
	}
}

func sendDailyAggregateReports(ctx context.Context, start, end time.Time) error {
	events, err := db.FetchDMARCEvents(ctx, start, end)
	if err != nil {
		return err
	}
	byPolicy := make(map[string][]db.DMARCEvent)
	for _, event := range events {
		if event.PolicyDomain == "" || len(event.PolicyRUA) == 0 {
			continue
		}
		byPolicy[event.PolicyDomain] = append(byPolicy[event.PolicyDomain], event)
	}

	for policyDomain, domainEvents := range byPolicy {
		recipients := selectReportRecipients(domainEvents)
		if len(recipients) == 0 {
			continue
		}
		xmlData, err := buildRUAXML(policyDomain, domainEvents, start, end)
		if err != nil {
			log.Printf("Failed to build RUA XML for %s: %v", policyDomain, err)
			continue
		}
		report := buildRUAEmail(policyDomain, recipients, xmlData, start, end)
		sender := reportSenderAddress()
		if err := enqueueReportEmail(ctx, sender, recipients, report); err != nil {
			log.Printf("Failed to enqueue RUA report for %s: %v", policyDomain, err)
		}
	}
	return nil
}

func selectReportRecipients(events []db.DMARCEvent) []string {
	counts := make(map[string]int)
	for _, event := range events {
		for _, addr := range event.PolicyRUA {
			counts[addr]++
		}
	}
	var recipients []string
	for addr := range counts {
		recipients = append(recipients, addr)
	}
	sort.Strings(recipients)
	return recipients
}

func buildRUFReport(result dns.DMARCResult, headerFromDomain, spfDomain, sourceIP string, spfResult dns.SPFResult, dkimDomains []string, headersOnly string) string {
	boundary := fmt.Sprintf("dmarc-ruf-%d", time.Now().UnixNano())
	toHeader := strings.Join(result.Policy.RUF, ", ")

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("From: %s\r\n", reportSenderAddress()))
	sb.WriteString(fmt.Sprintf("To: %s\r\n", toHeader))
	sb.WriteString(fmt.Sprintf("Subject: DMARC Failure Report for %s\r\n", headerFromDomain))
	sb.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z)))
	sb.WriteString(fmt.Sprintf("Message-ID: <%d@%s>\r\n", time.Now().UnixNano(), reportDomain()))
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString(fmt.Sprintf("Content-Type: multipart/report; report-type=feedback-report; boundary=\"%s\"\r\n", boundary))
	sb.WriteString("\r\n")

	sb.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	sb.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
	sb.WriteString("This is a DMARC failure report generated by the receiving server.\r\n\r\n")

	sb.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	sb.WriteString("Content-Type: message/feedback-report\r\n\r\n")
	sb.WriteString("Feedback-Type: auth-failure\r\n")
	sb.WriteString("User-Agent: puppy-eyes\r\n")
	sb.WriteString("Version: 1\r\n")
	sb.WriteString(fmt.Sprintf("Original-Mail-From: <%s>\r\n", spfDomain))
	sb.WriteString(fmt.Sprintf("Source-IP: %s\r\n", sourceIP))
	sb.WriteString(fmt.Sprintf("Reported-Domain: %s\r\n", result.PolicyDomain))
	sb.WriteString(fmt.Sprintf("Authentication-Results: %s; dmarc=%s header.from=%s\r\n", SERVER_IDENTITY, boolToPassFail(result.Pass), headerFromDomain))
	sb.WriteString("\r\n")

	sb.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	sb.WriteString("Content-Type: message/rfc822-headers\r\n\r\n")
	sb.WriteString(normalizeLineEndings(headersOnly))
	if !strings.HasSuffix(headersOnly, "\r\n") {
		sb.WriteString("\r\n")
	}

	sb.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
	return sb.String()
}

func buildRUAEmail(policyDomain string, recipients []string, xmlData []byte, start, end time.Time) string {
	boundary := fmt.Sprintf("dmarc-rua-%d", time.Now().UnixNano())
	toHeader := strings.Join(recipients, ", ")
	filename := fmt.Sprintf("dmarc-report-%s-%s.xml", policyDomain, start.Format("20060102"))

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("From: %s\r\n", reportSenderAddress()))
	sb.WriteString(fmt.Sprintf("To: %s\r\n", toHeader))
	sb.WriteString(fmt.Sprintf("Subject: DMARC Aggregate Report for %s\r\n", policyDomain))
	sb.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z)))
	sb.WriteString(fmt.Sprintf("Message-ID: <%d@%s>\r\n", time.Now().UnixNano(), reportDomain()))
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=\"%s\"\r\n", boundary))
	sb.WriteString("\r\n")

	sb.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	sb.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
	sb.WriteString("DMARC aggregate report attached.\r\n\r\n")

	sb.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	sb.WriteString(fmt.Sprintf("Content-Type: application/xml; name=\"%s\"\r\n", filename))
	sb.WriteString("Content-Transfer-Encoding: 7bit\r\n")
	sb.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=\"%s\"\r\n\r\n", filename))
	sb.Write(xmlData)
	sb.WriteString("\r\n")

	sb.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
	return sb.String()
}

func buildRUAXML(policyDomain string, events []db.DMARCEvent, start, end time.Time) ([]byte, error) {
	metadata := reportMetadata{
		OrgName:  SERVER_IDENTITY,
		Email:    reportSenderAddress(),
		ReportID: fmt.Sprintf("%s-%s", policyDomain, start.Format("20060102")),
		DateRange: reportDateRange{
			Begin: start.Unix(),
			End:   end.Unix(),
		},
	}

	policy := policyPublished{
		Domain: policyDomain,
	}
	if len(events) > 0 {
		policy.ADKIM = events[0].PolicyADKIM
		policy.ASPF = events[0].PolicyASPF
		policy.P = events[0].PolicyP
		policy.SP = events[0].PolicySP
		policy.PCT = events[0].PolicyPCT
	}

	records := aggregateDMARCRecords(events)
	feedback := reportFeedback{
		ReportMetadata:  metadata,
		PolicyPublished: policy,
		Records:         records,
	}

	buf := &bytes.Buffer{}
	buf.WriteString(xml.Header)
	enc := xml.NewEncoder(buf)
	enc.Indent("", "  ")
	if err := enc.Encode(feedback); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func aggregateDMARCRecords(events []db.DMARCEvent) []reportRecord {
	groups := make(map[dmarcAggregateKey][]db.DMARCEvent)
	for _, event := range events {
		key := dmarcAggregateKey{
			PolicyDomain: event.PolicyDomain,
			HeaderFrom:   event.HeaderFromDomain,
			SourceIP:     event.SourceIP,
			Disposition:  event.Disposition,
			SPFAligned:   event.SPFAligned,
			DKIMAligned:  event.DKIMAligned,
			SPFResult:    event.SPFResult,
			SPFDomain:    event.SPFDomain,
			DKIMDomains:  strings.Join(event.DKIMDomains, ","),
		}
		groups[key] = append(groups[key], event)
	}

	var records []reportRecord
	for key, group := range groups {
		row := reportRow{
			SourceIP: key.SourceIP,
			Count:    len(group),
			PolicyEvaluated: policyEvaluated{
				Disposition: key.Disposition,
				DKIM:        boolToPassFail(key.DKIMAligned),
				SPF:         boolToPassFail(key.SPFAligned),
			},
		}

		identifiers := reportIdentifiers{HeaderFrom: key.HeaderFrom}
		authResults := reportAuthResults{
			SPF: []spfAuthResult{{Domain: key.SPFDomain, Result: strings.ToLower(key.SPFResult)}},
		}

		dkimDomains := uniqueSplit(key.DKIMDomains)
		if len(dkimDomains) == 0 {
			authResults.DKIM = []dkimAuthResult{{Domain: key.HeaderFrom, Result: "fail"}}
		} else {
			for _, domain := range dkimDomains {
				authResults.DKIM = append(authResults.DKIM, dkimAuthResult{Domain: domain, Result: "pass"})
			}
		}

		records = append(records, reportRecord{
			Row:         row,
			Identifiers: identifiers,
			AuthResults: authResults,
		})
	}

	sort.Slice(records, func(i, j int) bool {
		if records[i].Row.SourceIP == records[j].Row.SourceIP {
			return records[i].Identifiers.HeaderFrom < records[j].Identifiers.HeaderFrom
		}
		return records[i].Row.SourceIP < records[j].Row.SourceIP
	})

	return records
}

func enqueueReportEmail(ctx context.Context, sender string, recipients []string, rawMessage string) error {
	emailID, err := db.Q.CreateEmail(ctx, db.CreateEmailParams{
		Sender:     sender,
		Recipients: recipients,
		Body:       rawMessage,
		SpfPass:    pgtype.Bool{Valid: false},
		DmarcPass:  pgtype.Bool{Valid: false},
		DkimPass:   pgtype.Bool{Valid: false},
	})
	if err != nil {
		return err
	}
	_, err = db.Q.EnqueueEmail(ctx, emailID)
	return err
}

func reportSenderAddress() string {
	domain := reportDomain()
	return fmt.Sprintf("postmaster@%s", domain)
}

func reportDomain() string {
	parts := strings.Split(SERVER_IDENTITY, ".")
	if len(parts) < 2 {
		return SERVER_IDENTITY
	}
	return SERVER_IDENTITY
}

func extractHeaderBlock(raw string) string {
	idx := strings.Index(raw, "\r\n\r\n")
	if idx != -1 {
		return raw[:idx+2]
	}
	idx = strings.Index(raw, "\n\n")
	if idx != -1 {
		return raw[:idx+1]
	}
	return raw
}

func normalizeLineEndings(input string) string {
	input = strings.ReplaceAll(input, "\r\n", "\n")
	input = strings.ReplaceAll(input, "\r", "\n")
	return strings.ReplaceAll(input, "\n", "\r\n")
}

func boolToPassFail(val bool) string {
	if val {
		return "pass"
	}
	return "fail"
}

func uniqueSplit(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	seen := make(map[string]struct{})
	var out []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		out = append(out, part)
	}
	return out
}

type reportFeedback struct {
	XMLName         xml.Name        `xml:"feedback"`
	ReportMetadata  reportMetadata  `xml:"report_metadata"`
	PolicyPublished policyPublished `xml:"policy_published"`
	Records         []reportRecord  `xml:"record"`
}

type reportMetadata struct {
	OrgName   string          `xml:"org_name"`
	Email     string          `xml:"email"`
	ReportID  string          `xml:"report_id"`
	DateRange reportDateRange `xml:"date_range"`
}

type reportDateRange struct {
	Begin int64 `xml:"begin"`
	End   int64 `xml:"end"`
}

type policyPublished struct {
	Domain string `xml:"domain"`
	ADKIM  string `xml:"adkim"`
	ASPF   string `xml:"aspf"`
	P      string `xml:"p"`
	SP     string `xml:"sp,omitempty"`
	PCT    int    `xml:"pct"`
}

type reportRecord struct {
	Row         reportRow         `xml:"row"`
	Identifiers reportIdentifiers `xml:"identifiers"`
	AuthResults reportAuthResults `xml:"auth_results"`
}

type reportRow struct {
	SourceIP        string          `xml:"source_ip"`
	Count           int             `xml:"count"`
	PolicyEvaluated policyEvaluated `xml:"policy_evaluated"`
}

type policyEvaluated struct {
	Disposition string `xml:"disposition"`
	DKIM        string `xml:"dkim"`
	SPF         string `xml:"spf"`
}

type reportIdentifiers struct {
	HeaderFrom string `xml:"header_from"`
}

type reportAuthResults struct {
	SPF  []spfAuthResult  `xml:"spf"`
	DKIM []dkimAuthResult `xml:"dkim"`
}

type spfAuthResult struct {
	Domain string `xml:"domain"`
	Result string `xml:"result"`
}

type dkimAuthResult struct {
	Domain string `xml:"domain"`
	Result string `xml:"result"`
}

func nextUTCMidnight() time.Time {
	now := time.Now().UTC()
	y, m, d := now.Date()
	next := time.Date(y, m, d+1, 0, 0, 0, 0, time.UTC)
	return next
}
