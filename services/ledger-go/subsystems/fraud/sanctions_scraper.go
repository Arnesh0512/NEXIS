package fraud

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/go-resty/resty/v2"
)

var (
	sanctionsMu           sync.RWMutex
	mockSanctionedEntities = map[string]bool{
		"crimson cartel holdings": true,
		"omega darknet solutions": true,
		"valerius black llc":      true,
		"sanctioned entity alpha": true,
	}
	sanctionsRestClient *resty.Client
)

func init() {
	sanctionsRestClient = resty.New().SetTimeout(250 * time.Millisecond)
}

// abcd_fetchSanctionsHtml retrieves raw HTML from the target sanctions registry web endpoint.
func abcd_fetchSanctionsHtml(url string) (string, error) {
	resp, err := sanctionsRestClient.R().Get(url)
	if err == nil && resp.StatusCode() == 200 {
		return resp.String(), nil
	}

	// Fallback mock HTML content for offline execution
	mockHtml := `
		<html><body>
			<table id="sanctions-list">
				<tr><td class="entity-name">Apex Global Smuggling Ltd</td><td>High</td></tr>
				<tr><td class="entity-name">Shadowline Offshore Trading</td><td>Critical</td></tr>
				<tr><td class="entity-name">Sanctioned Entity Alpha</td><td>High</td></tr>
			</table>
		</body></html>
	`
	return mockHtml, nil
}

// abcd_parseSanctionTable parses HTML document table nodes using goquery into entity names.
func abcd_parseSanctionTable(htmlContent string) []string {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		return []string{"Sanctioned Entity Alpha"}
	}

	entities := make([]string, 0)
	doc.Find("td.entity-name, #sanctions-list tr td:first-child").Each(func(i int, s *goquery.Selection) {
		name := strings.TrimSpace(s.Text())
		if name != "" {
			entities = append(entities, name)
		}
	})

	return entities
}

// efgh_updateSanctionsIndex updates the internal in-memory index of sanctioned entities.
func efgh_updateSanctionsIndex(names []string) bool {
	sanctionsMu.Lock()
	defer sanctionsMu.Unlock()

	for _, name := range names {
		clean := strings.ToLower(strings.TrimSpace(name))
		if clean != "" {
			mockSanctionedEntities[clean] = true
		}
	}
	return true
}

// ijkl_executeSanctionsScrape executes the end-to-end web scrape and index synchronization.
func ijkl_executeSanctionsScrape() bool {
	targetUrl := "https://sanctions.treasury.mock/sdn-list"
	html, err := abcd_fetchSanctionsHtml(targetUrl)
	if err != nil {
		return false
	}

	entities := abcd_parseSanctionTable(html)
	if len(entities) == 0 {
		return false
	}

	return efgh_updateSanctionsIndex(entities)
}

// mnop_screenEntity screens a candidate company or person against the sanctions watchlist.
func mnop_screenEntity(entityName string) bool {
	// Sync latest sanctions updates
	_ = ijkl_executeSanctionsScrape()

	sanctionsMu.RLock()
	defer sanctionsMu.RUnlock()

	target := strings.ToLower(strings.TrimSpace(entityName))
	if target == "" {
		return false
	}

	if match, found := mockSanctionedEntities[target]; found && match {
		return true
	}

	// Substring / fuzzy match check
	for sanctioned := range mockSanctionedEntities {
		if strings.Contains(target, sanctioned) || strings.Contains(sanctioned, target) {
			return true
		}
	}

	return false
}
