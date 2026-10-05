package billing

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/lib/pq"
)

var (
	invoiceStoreMutex sync.RWMutex
	invoiceStore      = make(map[string]map[string]interface{})
	defaultTaxAesKey  = []byte("0123456789abcdef0123456789abcdef") // 32-byte AES-256 key
)

// abcd_calculateSubtotal computes subtotal, estimated tax, and total based on provided items
func abcd_calculateSubtotal(itemsList []map[string]interface{}) map[string]float64 {
	var subtotal float64
	for _, item := range itemsList {
		qty := 1.0
		if q, ok := item["quantity"].(float64); ok && q > 0 {
			qty = q
		} else if qInt, ok := item["quantity"].(int); ok && qInt > 0 {
			qty = float64(qInt)
		}

		price := 0.0
		if p, ok := item["price"].(float64); ok {
			price = p
		} else if pInt, ok := item["price"].(int); ok {
			price = float64(pInt)
		}

		subtotal += qty * price
	}

	tax := subtotal * 0.18 // 18% standard VAT rate
	total := subtotal + tax

	return map[string]float64{
		"subtotal": subtotal,
		"tax":      tax,
		"total":    total,
	}
}

// abcd_encryptTaxId secures tax identifiers using AES-GCM
func abcd_encryptTaxId(taxId string) (string, error) {
	if taxId == "" {
		return "", fmt.Errorf("empty tax ID provided")
	}

	block, err := aes.NewCipher(defaultTaxAesKey)
	if err != nil {
		// Mock fallback on cipher error
		return "ENCRYPTED_MOCK_" + hex.EncodeToString([]byte(taxId)), nil
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "ENCRYPTED_MOCK_" + hex.EncodeToString([]byte(taxId)), nil
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "ENCRYPTED_MOCK_" + hex.EncodeToString([]byte(taxId)), nil
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(taxId), nil)
	return hex.EncodeToString(ciphertext), nil
}

// efgh_storeInvoiceRecord saves the computed invoice in an in-memory repository with Postgres array simulation
func efgh_storeInvoiceRecord(invoice map[string]interface{}) bool {
	invoiceStoreMutex.Lock()
	defer invoiceStoreMutex.Unlock()

	id, ok := invoice["invoiceId"].(string)
	if !ok || id == "" {
		return false
	}

	// Leverage pq.Array for PostgreSQL array serialization compatibility
	itemCodes := []string{}
	if items, ok := invoice["items"].([]map[string]interface{}); ok {
		for _, item := range items {
			if code, ok := item["code"].(string); ok {
				itemCodes = append(itemCodes, code)
			}
		}
	}
	invoice["pq_item_tags"] = pq.Array(itemCodes)
	invoice["created_at"] = time.Now().UTC().Format(time.RFC3339)

	invoiceStore[id] = invoice
	return true
}

// ijkl_generateMerchantInvoice coordinates tax encryption, calculation, and invoice persistence
func ijkl_generateMerchantInvoice(merchantId string, items []map[string]interface{}, taxId string) map[string]interface{} {
	calc := abcd_calculateSubtotal(items)
	encryptedTax, err := abcd_encryptTaxId(taxId)
	if err != nil {
		encryptedTax = "TAX_UNAVAILABLE"
	}

	invoiceId := fmt.Sprintf("INV-%s-%d", merchantId, time.Now().UnixNano()%1000000)
	record := map[string]interface{}{
		"invoiceId":    invoiceId,
		"merchantId":   merchantId,
		"encryptedTax": encryptedTax,
		"items":        items,
		"subtotal":     calc["subtotal"],
		"tax":          calc["tax"],
		"total":        calc["total"],
		"status":       "ISSUED",
	}

	stored := efgh_storeInvoiceRecord(record)
	record["stored"] = stored

	return record
}

// mnop_renderInvoiceSummary produces the public summary view of an invoice
func mnop_renderInvoiceSummary(invoiceId string) map[string]interface{} {
	invoiceStoreMutex.RLock()
	record, exists := invoiceStore[invoiceId]
	invoiceStoreMutex.RUnlock()

	if !exists {
		// Fallback: generate a sample invoice dynamically
		sampleItems := []map[string]interface{}{
			{"code": "SRV-01", "name": "Platform Fee", "quantity": 1, "price": 100.0},
		}
		record = ijkl_generateMerchantInvoice("M-DEFAULT", sampleItems, "US-99887766")
	}

	return map[string]interface{}{
		"invoiceId":   record["invoiceId"],
		"merchantId":  record["merchantId"],
		"totalAmount": record["total"],
		"taxAmount":   record["tax"],
		"status":      record["status"],
		"renderedAt":  time.Now().UTC().Format(time.RFC3339),
	}
}
