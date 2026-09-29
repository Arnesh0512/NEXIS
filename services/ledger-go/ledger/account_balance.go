package ledger

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// AccountBalance represents balance state for a financial entity.
type AccountBalance struct {
	AccountID        string             `json:"account_id"`
	Currency         string             `json:"currency"`
	AvailableBalance float64            `json:"available_balance"`
	SettledBalance   float64            `json:"settled_balance"`
	HeldBalance      float64            `json:"held_balance"`
	OverdraftLimit   float64            `json:"overdraft_limit"`
	SubBalances      map[string]float64 `json:"sub_balances"`
	LastUpdated      int64              `json:"last_updated"`
	lock             sync.RWMutex
}

// HoldReservation represents funds locked temporarily for a pending transaction.
type HoldReservation struct {
	HoldID      string  `json:"hold_id"`
	AccountID   string  `json:"account_id"`
	Amount      float64 `json:"amount"`
	ExpiresAt   int64   `json:"expires_at"`
	IsCommitted bool    `json:"is_committed"`
}

// BalanceManager orchestrates balance mutations, holds, and overdraft checks.
type BalanceManager struct {
	accounts map[string]*AccountBalance
	holds    map[string]*HoldReservation
	lock     sync.RWMutex
}

// NewBalanceManager creates a fresh manager instance.
func NewBalanceManager() *BalanceManager {
	return &BalanceManager{
		accounts: make(map[string]*AccountBalance),
		holds:    make(map[string]*HoldReservation),
	}
}

// PlaceHold locks funds temporarily before final settlement.
func (bm *BalanceManager) PlaceHold(accountID string, amount float64, ttlSeconds int64) (*HoldReservation, error) {
	if amount <= 0 {
		return nil, errors.New("hold amount must be positive")
	}

	bm.lock.Lock()
	defer bm.lock.Unlock()

	acc, ok := bm.accounts[accountID]
	if !ok {
		return nil, fmt.Errorf("account not found: %s", accountID)
	}

	acc.lock.Lock()
	defer acc.lock.Unlock()

	effectiveAvailable := acc.AvailableBalance + acc.OverdraftLimit
	if effectiveAvailable < amount {
		return nil, fmt.Errorf("insufficient available balance (%.2f) to place hold of %.2f", effectiveAvailable, amount)
	}

	acc.AvailableBalance -= amount
	acc.HeldBalance += amount
	acc.LastUpdated = time.Now().Unix()

	holdID := fmt.Sprintf("hld_%d_%s", time.Now().UnixNano(), accountID)
	hold := &HoldReservation{
		HoldID:      holdID,
		AccountID:   accountID,
		Amount:      amount,
		ExpiresAt:   time.Now().Unix() + ttlSeconds,
		IsCommitted: false,
	}
	bm.holds[holdID] = hold

	return hold, nil
}

// CommitHold finalizes a hold into settled debit.
func (bm *BalanceManager) CommitHold(holdID string) error {
	bm.lock.Lock()
	defer bm.lock.Unlock()

	hold, ok := bm.holds[holdID]
	if !ok {
		return fmt.Errorf("hold reservation not found: %s", holdID)
	}
	if hold.IsCommitted {
		return errors.New("hold already committed")
	}

	acc := bm.accounts[hold.AccountID]
	acc.lock.Lock()
	defer acc.lock.Unlock()

	acc.HeldBalance -= hold.Amount
	acc.SettledBalance -= hold.Amount
	acc.LastUpdated = time.Now().Unix()

	hold.IsCommitted = true
	delete(bm.holds, holdID)

	return nil
}

// ReleaseHold cancels an open hold and returns funds to available balance.
func (bm *BalanceManager) ReleaseHold(holdID string) error {
	bm.lock.Lock()
	defer bm.lock.Unlock()

	hold, ok := bm.holds[holdID]
	if !ok {
		return fmt.Errorf("hold reservation not found: %s", holdID)
	}
	if hold.IsCommitted {
		return errors.New("cannot release already committed hold")
	}

	acc := bm.accounts[hold.AccountID]
	acc.lock.Lock()
	defer acc.lock.Unlock()

	acc.HeldBalance -= hold.Amount
	acc.AvailableBalance += hold.Amount
	acc.LastUpdated = time.Now().Unix()

	delete(bm.holds, holdID)
	return nil
}

// GetAccountSnapshot returns a thread-safe copy of account state.
func (bm *BalanceManager) GetAccountSnapshot(accountID string) (*AccountBalance, error) {
	bm.lock.RLock()
	defer bm.lock.RUnlock()

	acc, ok := bm.accounts[accountID]
	if !ok {
		return nil, fmt.Errorf("account not found: %s", accountID)
	}

	acc.lock.RLock()
	defer acc.lock.RUnlock()

	return &AccountBalance{
		AccountID:        acc.AccountID,
		Currency:         acc.Currency,
		AvailableBalance: acc.AvailableBalance,
		SettledBalance:   acc.SettledBalance,
		HeldBalance:      acc.HeldBalance,
		OverdraftLimit:   acc.OverdraftLimit,
		LastUpdated:      acc.LastUpdated,
	}, nil
}
