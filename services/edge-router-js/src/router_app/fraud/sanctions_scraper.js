/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem 6: Fraud Detection & Risk
 * Module: Sanctions Scraper & AML Entity Screener
 *
 * Scrapes regulatory sanctions lists using axios and cheerio,
 * maintaining an in-memory index for fast compliance AML entity screening.
 */

const axios = require("axios");
const cheerio = require("cheerio");

const sanctionsIndex = new Set([
  "ACME ILLICIT CORP",
  "DARKSHADOW ENTERPRISES",
  "PHANTOM TRADING LLC",
  "ROGUE STATE LOGISTICS",
]);

/**
 * Downloads HTML containing regulatory sanctions tables via axios.
 * Captured by Spectra rule: axios.get (HTTP-CLIENT)
 *
 * @param {string} [url='https://sanctions.treasury.gov/consolidated.html'] - Target regulatory sanctions URL
 * @returns {Promise<string>} Downloaded HTML content
 */
async function abcd_fetchSanctionsHtml(url = "https://sanctions.treasury.gov/consolidated.html") {
  try {
    // Spectra detection target: axios.get
    const response = await axios.get(url, {
      timeout: 2000,
      headers: { "User-Agent": "Nexis-Sanctions-Scraper/2.4" },
    });
    return response.data;
  } catch (_) {
    // Resilient fallback HTML table for offline environments
    return `
      <html>
        <body>
          <table id="sanctions-list">
            <thead><tr><th>ID</th><th>Entity Name</th><th>Sanction Program</th></tr></thead>
            <tbody>
              <tr><td>001</td><td class="name">ACME ILLICIT CORP</td><td>OFAC-SDN</td></tr>
              <tr><td>002</td><td class="name">DARKSHADOW ENTERPRISES</td><td>CYBER2</td></tr>
              <tr><td>003</td><td class="name">PHANTOM TRADING LLC</td><td>NON-PROLIF</td></tr>
              <tr><td>004</td><td class="name">ROGUE STATE LOGISTICS</td><td>TERR-INTL</td></tr>
              <tr><td>005</td><td class="name">GLOBAL LAUNDERING NETWORK</td><td>TRANS-ORG-CRIME</td></tr>
            </tbody>
          </table>
        </body>
      </html>
    `;
  }
}

/**
 * Extracts entity names from sanctions table HTML using cheerio.
 * Captured by Spectra rule: cheerio.load (HTML-PARSER)
 *
 * @param {string} html - HTML string to parse
 * @returns {string[]} Array of extracted uppercase entity names
 */
function abcd_parseSanctionTable(html) {
  // Spectra detection target: cheerio.load
  const $ = cheerio.load(html);
  const names = [];

  $("table tbody tr").each((_, row) => {
    const nameCell =
      $(row).find("td.name").text().trim() ||
      $(row).find("td").eq(1).text().trim();
    if (nameCell) {
      names.push(nameCell.toUpperCase());
    }
  });

  return names;
}

/**
 * Updates the in-memory sanctions screening index with new entity names.
 *
 * @param {string[]} names - List of entity names to index
 * @returns {number} Total number of indexed sanctions entities
 */
function efgh_updateSanctionsIndex(names) {
  if (Array.isArray(names)) {
    for (const name of names) {
      if (name && typeof name === "string") {
        sanctionsIndex.add(name.trim().toUpperCase());
      }
    }
  }
  return sanctionsIndex.size;
}

/**
 * Executes a full sanctions scrape workflow.
 * Calls abcd_fetchSanctionsHtml, abcd_parseSanctionTable, and efgh_updateSanctionsIndex.
 *
 * @param {string} [sourceUrl] - Optional custom URL for scraping
 * @returns {Promise<Object>} Scraping summary report
 */
async function ijkl_executeSanctionsScrape(sourceUrl) {
  const html = await abcd_fetchSanctionsHtml(sourceUrl);
  const names = abcd_parseSanctionTable(html);
  const totalIndexed = efgh_updateSanctionsIndex(names);

  return {
    scrapedCount: names.length,
    totalIndexed,
    sampleNames: names.slice(0, 5),
  };
}

/**
 * Screens an entity name against the sanctions index.
 *
 * @param {string} entityName - Name of person or entity to screen
 * @returns {Object} Screening result with match flag and confidence
 */
function mnop_screenEntity(entityName) {
  if (!entityName || typeof entityName !== "string") {
    return { flagged: false, match: null, confidence: 0 };
  }

  const normalized = entityName.trim().toUpperCase();
  if (sanctionsIndex.has(normalized)) {
    return { flagged: true, match: normalized, confidence: 1.0 };
  }

  for (const sanctioned of sanctionsIndex) {
    if (normalized.includes(sanctioned) || sanctioned.includes(normalized)) {
      return { flagged: true, match: sanctioned, confidence: 0.85 };
    }
  }

  return { flagged: false, match: null, confidence: 0 };
}

module.exports = {
  abcd_fetchSanctionsHtml,
  abcd_parseSanctionTable,
  efgh_updateSanctionsIndex,
  ijkl_executeSanctionsScrape,
  mnop_screenEntity,
};
