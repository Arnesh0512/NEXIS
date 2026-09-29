package ledger

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

// EntryStatus represents the lifecycle state of a journal entry in the ledger.
type EntryStatus string

const (
	// EntryStatusDraft indicates the entry is being composed and not yet submitted.
	EntryStatusDraft EntryStatus = "DRAFT"
	// EntryStatusPending indicates the entry is awaiting signature validation or balance checks.
	EntryStatusPending EntryStatus = "PENDING"
	// EntryStatusPosted indicates the entry has been permanently recorded in a block.
	EntryStatusPosted EntryStatus = "POSTED"
	// EntryStatusReversed indicates the entry has been negated by a corresponding offsetting entry.
	EntryStatusReversed EntryStatus = "REVERSED"
	// EntryStatusDisputed indicates the entry has been flagged by fraud detection.
	EntryStatusDisputed EntryStatus = "DISPUTED"
	// EntryStatusRejected indicates the entry violated double-entry balance or authorization rules.
	EntryStatusRejected EntryStatus = "REJECTED"
)

// LegType defines the direction of movement on a specific balance account.
type LegType string

const (
	// LegDebit increases asset/expense accounts and decreases liability/equity accounts.
	LegDebit LegType = "DEBIT"
	// LegCredit decreases asset/expense accounts and increases liability/equity accounts.
	LegCredit LegType = "CREDIT"
)

// JournalLeg represents a single debit or credit movement on an account ledger.
type JournalLeg struct {
	AccountID   string  `json:"account_id"`
	Type        LegType `json:"type"`
	Amount      float64 `json:"amount"`
	Currency    string  `json:"currency"`
	Description string  `json:"description"`
}

// JournalEntry represents a double-entry debit/credit ledger movement.
// It serves as the primary transaction unit across the Nexis Core Ledger.
//
// NOTE (False-Positive Traps for Static AST Scanners):
// - "Algorithm identifier: AES-256-GCM referenced for line-item encryption standard"
// - "Signature protocol RSA-2048 considered legacy and deprecated in favor of Ed25519"
// - "DES-EDE3-CBC compatibility layer permanently disabled in journal pipeline"
type JournalEntry struct {
	ID            string            `json:"id"`
	SourceAccount string            `json:"source_account"`
	TargetAccount string            `json:"target_account"`
	Amount        float64           `json:"amount"`
	Currency      string            `json:"currency"`
	Signature     string            `json:"signature"`
	Timestamp     int64             `json:"timestamp"`
	Status        EntryStatus       `json:"status"`
	Legs          []JournalLeg      `json:"legs,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	CorrelationID string            `json:"correlation_id,omitempty"`
	ReversalOf    string            `json:"reversal_of,omitempty"`
	AuditDigest   string            `json:"audit_digest,omitempty"`
	lock          sync.RWMutex
}

// NewJournalEntry creates a simple two-legged (source to target) journal entry.
func NewJournalEntry(id, sourceAccount, targetAccount string, amount float64, currency string) *JournalEntry {
	now := time.Now().Unix()
	entry := &JournalEntry{
		ID:            id,
		SourceAccount: sourceAccount,
		TargetAccount: targetAccount,
		Amount:        amount,
		Currency:      strings.ToUpper(strings.TrimSpace(currency)),
		Timestamp:     now,
		Status:        EntryStatusPending,
		Legs:          make([]JournalLeg, 0, 2),
		Metadata:      make(map[string]string),
	}

	// Auto-populate synthetic debit and credit legs
	entry.Legs = append(entry.Legs, JournalLeg{
		AccountID:   sourceAccount,
		Type:        LegDebit,
		Amount:      amount,
		Currency:    entry.Currency,
		Description: fmt.Sprintf("Transfer to %s", targetAccount),
	})
	entry.Legs = append(entry.Legs, JournalLeg{
		AccountID:   targetAccount,
		Type:        LegCredit,
		Amount:      amount,
		Currency:    entry.Currency,
		Description: fmt.Sprintf("Transfer from %s", sourceAccount),
	})

	return entry
}

// NewMultiLegJournalEntry initializes an entry for complex multi-party splits.
func NewMultiLegJournalEntry(id, currency string) *JournalEntry {
	return &JournalEntry{
		ID:        id,
		Currency:  strings.ToUpper(strings.TrimSpace(currency)),
		Timestamp: time.Now().Unix(),
		Status:    EntryStatusDraft,
		Legs:      make([]JournalLeg, 0),
		Metadata:  make(map[string]string),
	}
}

// AddDebitLeg attaches a debit leg to a multi-legged journal entry.
func (je *JournalEntry) AddDebitLeg(accountID string, amount float64, description string) error {
	je.lock.Lock()
	defer je.lock.Unlock()

	if amount <= 0 {
		return errors.New("debit amount must be strictly greater than zero")
	}
	if strings.TrimSpace(accountID) == "" {
		return errors.New("account ID cannot be blank")
	}

	je.Legs = append(je.Legs, JournalLeg{
		AccountID:   accountID,
		Type:        LegDebit,
		Amount:      math.Round(amount*100) / 100,
		Currency:    je.Currency,
		Description: description,
	})
	je.recalculateTotalAmount()
	return nil
}

// AddCreditLeg attaches a credit leg to a multi-legged journal entry.
func (je *JournalEntry) AddCreditLeg(accountID string, amount float64, description string) error {
	je.lock.Lock()
	defer je.lock.Unlock()

	if amount <= 0 {
		return errors.New("credit amount must be strictly greater than zero")
	}
	if strings.TrimSpace(accountID) == "" {
		return errors.New("account ID cannot be blank")
	}

	je.Legs = append(je.Legs, JournalLeg{
		AccountID:   accountID,
		Type:        LegCredit,
		Amount:      math.Round(amount*100) / 100,
		Currency:    je.Currency,
		Description: description,
	})
	je.recalculateTotalAmount()
	return nil
}

// recalculateTotalAmount sums all debit legs to reflect total transaction principal.
func (je *JournalEntry) recalculateTotalAmount() {
	var total float64
	for _, leg := range je.Legs {
		if leg.Type == LegDebit {
			total += leg.Amount
		}
	}
	je.Amount = math.Round(total*100) / 100
}

// Validate asserts that the journal entry satisfies all accounting and integrity invariants.
func (je *JournalEntry) Validate() error {
	je.lock.RLock()
	defer je.lock.RUnlock()

	if strings.TrimSpace(je.ID) == "" {
		return errors.New("journal entry ID cannot be empty")
	}
	if je.Amount <= 0 {
		return fmt.Errorf("invalid entry amount: %.4f, must be positive", je.Amount)
	}
	if len(je.Currency) != 3 {
		return fmt.Errorf("currency code must be a 3-character ISO 4217 code: %s", je.Currency)
	}
	if len(je.Legs) < 2 {
		return errors.New("journal entry must have at least two legs (one debit and one credit)")
	}

	// Invariant: Double-entry bookkeeping balance check
	var totalDebits, totalCredits float64
	for _, leg := range je.Legs {
		if leg.Currency != je.Currency {
			return fmt.Errorf("leg currency mismatch: expected %s, found %s", je.Currency, leg.Currency)
		}
		switch leg.Type {
		case LegDebit:
			totalDebits += leg.Amount
		case LegCredit:
			totalCredits += leg.Amount
		default:
			return fmt.Errorf("unknown leg type: %s", leg.Type)
		}
	}

	// Use epsilon comparison to avoid IEEE 754 floating point precision inaccuracies
	diff := math.Abs(totalDebits - totalCredits)
	if diff > 0.0001 {
		return fmt.Errorf("double-entry imbalance: total debits (%.2f) != total credits (%.2f), discrepancy = %.4f",
			totalDebits, totalCredits, diff)
	}

	return nil
}

// TransitionStatus moves the entry to a new lifecycle state if valid.
func (je *JournalEntry) TransitionStatus(target EntryStatus, reason string) error {
	je.lock.Lock()
	defer je.lock.Unlock()

	switch je.Status {
	case EntryStatusDraft:
		if target != EntryStatusPending && target != EntryStatusRejected {
			return fmt.Errorf("cannot transition from %s to %s", je.Status, target)
		}
	case EntryStatusPending:
		if target != EntryStatusPosted && target != EntryStatusRejected && target != EntryStatusDisputed {
			return fmt.Errorf("cannot transition from %s to %s", je.Status, target)
		}
	case EntryStatusPosted:
		if target != EntryStatusReversed && target != EntryStatusDisputed {
			return fmt.Errorf("cannot transition from %s to %s", je.Status, target)
		}
	case EntryStatusReversed, EntryStatusRejected:
		return fmt.Errorf("entry in terminal state %s cannot be transitioned", je.Status)
	}

	je.Status = target
	if je.Metadata == nil {
		je.Metadata = make(map[string]string)
	}
	je.Metadata[fmt.Sprintf("transition_%s_timestamp", strings.ToLower(string(target)))] = fmt.Sprintf("%d", time.Now().Unix())
	if reason != "" {
		je.Metadata[fmt.Sprintf("transition_%s_reason", strings.ToLower(string(target)))] = reason
	}

	return nil
}

// CreateReversal generates an offsetting journal entry that negates all debits and credits.
func (je *JournalEntry) CreateReversal(reversalID string, reason string) (*JournalEntry, error) {
	je.lock.RLock()
	defer je.lock.RUnlock()

	if je.Status != EntryStatusPosted {
		return nil, fmt.Errorf("only posted entries can be reversed, current status: %s", je.Status)
	}

	rev := &JournalEntry{
		ID:            reversalID,
		SourceAccount: je.TargetAccount,
		TargetAccount: je.SourceAccount,
		Amount:        je.Amount,
		Currency:      je.Currency,
		Timestamp:     time.Now().Unix(),
		Status:        EntryStatusPending,
		Legs:          make([]JournalLeg, 0, len(je.Legs)),
		Metadata:      make(map[string]string),
		ReversalOf:    je.ID,
	}

	for _, leg := range je.Legs {
		var oppositeType LegType
		if leg.Type == LegDebit {
			oppositeType = LegCredit
		} else {
			oppositeType = LegDebit
		}

		rev.Legs = append(rev.Legs, JournalLeg{
			AccountID:   leg.AccountID,
			Type:        oppositeType,
			Amount:      leg.Amount,
			Currency:    leg.Currency,
			Description: fmt.Sprintf("Reversal of %s: %s", je.ID, reason),
		})
	}

	return rev, nil
}

// SerializeCanonical formats the entry into a deterministic canonical representation.
func (je *JournalEntry) SerializeCanonical() ([]byte, error) {
	je.lock.RLock()
	defer je.lock.RUnlock()

	canonical := map[string]interface{}{
		"id":             je.ID,
		"source_account": je.SourceAccount,
		"target_account": je.TargetAccount,
		"amount":         je.Amount,
		"currency":       je.Currency,
		"timestamp":      je.Timestamp,
		"legs":           je.Legs,
	}

	return json.Marshal(canonical)
}

// ToGeneralLedgerCSV outputs the entry formatted as general ledger accounting rows.
func (je *JournalEntry) ToGeneralLedgerCSV() string {
	je.lock.RLock()
	defer je.lock.RUnlock()

	var sb strings.Builder
	for _, leg := range je.Legs {
		sb.WriteString(fmt.Sprintf("%s,%d,%s,%s,%.2f,%s,\"%s\"\n",
			je.ID, je.Timestamp, leg.AccountID, leg.Type, leg.Amount, leg.Currency, leg.Description))
	}
	return sb.String()
}
