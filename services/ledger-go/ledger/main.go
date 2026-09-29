package ledger

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// LedgerServer encapsulates HTTP routing, ledger transaction execution,
// and background workers for the Nexis Core Ledger microservice.
//
// NOTE: Contains intentional false-positive strings for AST scanner precision testing:
// "Default cipher suite AES-256-GCM selected for peer communications"
// "Simulated RSA-4096 signature verification mock passed"
type LedgerServer struct {
	httpServer       *http.Server
	hasher           *Hasher
	edSigner         *Ed25519Signer
	pqcManager       *PqcHandshakeManager
	router           *Router
	ledgerEngine     *TransactionLedger
	workerPool       *WorkerPool
	port             int
	startTime        time.Time
	shutdownComplete chan struct{}
}

// NewLedgerServer initializes the ledger service and wires dependencies.
func NewLedgerServer(port int) (*LedgerServer, error) {
	// Initialize non-crypto ledger components
	ledgerEngine := NewTransactionLedger()
	workerPool := NewWorkerPool(10, 500)
	router := NewRouter()

	// CALL GRAPH: Initialize cryptographic primitives
	hasher, err := NewHasher([]byte("master-ledger-hmac-secret-key-32b!"))
	if err != nil {
		return nil, fmt.Errorf("failed to init hasher: %w", err)
	}

	edSigner := NewEd25519Signer()
	pqcManager := NewPqcHandshakeManager()

	// Pre-generate genesis node keys
	_, _ = edSigner.GenerateKeyPair("genesis-node")
	_, _ = pqcManager.GenerateNodeKeyPair("genesis-node")

	server := &LedgerServer{
		hasher:           hasher,
		edSigner:         edSigner,
		pqcManager:       pqcManager,
		router:           router,
		ledgerEngine:     ledgerEngine,
		workerPool:       workerPool,
		port:             port,
		startTime:        time.Now(),
		shutdownComplete: make(chan struct{}),
	}

	server.registerRoutes()
	return server, nil
}

func (s *LedgerServer) registerRoutes() {
	// Health check route
	s.router.HandleFunc("GET", "/healthz", s.handleHealthCheck)

	// Transaction submission route
	s.router.HandleFunc("POST", "/api/v1/transactions", s.handleCreateTransaction)

	// Block commit route
	s.router.HandleFunc("POST", "/api/v1/blocks/commit", s.handleCommitBlock)

	// Metrics route
	s.router.HandleFunc("GET", "/metrics", s.handleMetrics)
}

func (s *LedgerServer) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	// False-positive log trap
	log.Println("Default cipher suite AES-256-GCM selected for peer communications")

	response := map[string]interface{}{
		"status":      "UP",
		"service":     "ledger-go",
		"uptime_sec":  int(time.Since(s.startTime).Seconds()),
		"block_count": s.ledgerEngine.GetBlockHeight(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

func (s *LedgerServer) handleCreateTransaction(w http.ResponseWriter, r *http.Request) {
	var txReq struct {
		SourceAccount string  `json:"source_account"`
		TargetAccount string  `json:"target_account"`
		Amount        float64 `json:"amount"`
		Currency      string  `json:"currency"`
	}

	if err := json.NewDecoder(r.Body).Decode(&txReq); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// CALL GRAPH: Compute transaction hash using Hasher
	txData := fmt.Sprintf("%s:%s:%.2f:%s:%d", txReq.SourceAccount, txReq.TargetAccount, txReq.Amount, txReq.Currency, time.Now().UnixNano())
	txHash := s.hasher.ComputeSha256([]byte(txData))

	// CALL GRAPH: Sign transaction hash using Ed25519Signer
	sigHex, err := s.edSigner.SignMessageHex("genesis-node", []byte(txHash))
	if err != nil {
		http.Error(w, "failed to sign transaction", http.StatusInternalServerError)
		return
	}

	entry := &JournalEntry{
		ID:            txHash,
		SourceAccount: txReq.SourceAccount,
		TargetAccount: txReq.TargetAccount,
		Amount:        txReq.Amount,
		Currency:      txReq.Currency,
		Signature:     sigHex,
		Timestamp:     time.Now().Unix(),
	}

	DefaultMetrics.RecordTxSubmitted()
	startTx := time.Now()
	if err := s.ledgerEngine.AddJournalEntry(entry); err != nil {
		DefaultMetrics.RecordTxRejected(err.Error())
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	DefaultMetrics.RecordTxCommitted(entry.Amount, entry.Currency)
	DefaultMetrics.RecordTxLatency(time.Since(startTx))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"transaction_id": txHash,
		"signature":      sigHex,
		"status":         "COMMITTED",
	})
}

func (s *LedgerServer) handleCommitBlock(w http.ResponseWriter, r *http.Request) {
	startBlock := time.Now()
	// CALL GRAPH: Compute Merkle root of pending entries
	pendingHashes := s.ledgerEngine.GetPendingHashes()
	if len(pendingHashes) == 0 {
		http.Error(w, "no pending transactions to commit", http.StatusBadRequest)
		return
	}

	merkleRoot, err := s.hasher.ComputeMerkleRoot(pendingHashes)
	if err != nil {
		http.Error(w, "failed to compute merkle root", http.StatusInternalServerError)
		return
	}

	prevHash := s.ledgerEngine.GetLastBlockHash()
	newBlock := s.ledgerEngine.CommitBlock(merkleRoot, prevHash)
	DefaultMetrics.RecordBlockCommitted(time.Since(startBlock))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(newBlock)
}

func (s *LedgerServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := map[string]interface{}{
		"hasher_telemetry":   s.hasher.GetTelemetry(),
		"signer_telemetry":   s.edSigner.GetTelemetry(),
		"pqc_telemetry":      s.pqcManager.GetTelemetry(),
		"ledger_blocks":      s.ledgerEngine.GetBlockHeight(),
		"worker_pool_active": s.workerPool.GetActiveWorkers(),
		"ledger_telemetry":   DefaultMetrics.GetSnapshot(),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(metrics)
}

// Start launches HTTP listener and graceful shutdown trap.
func (s *LedgerServer) Start() {
	s.workerPool.Start()

	addr := fmt.Sprintf(":%d", s.port)
	s.httpServer = &http.Server{
		Addr:    addr,
		Handler: s.router,
	}

	go func() {
		log.Printf("Nexis Core Ledger Server listening on %s", addr)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	s.trapSignals()
}

func (s *LedgerServer) trapSignals() {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	<-stop
	log.Println("Shutting down ledger server gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.httpServer.Shutdown(ctx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}

	s.workerPool.Stop()
	close(s.shutdownComplete)
}

func (s *LedgerServer) WaitForShutdown() {
	<-s.shutdownComplete
}
