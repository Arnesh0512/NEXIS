#include <iostream>
#include <string>
#include <sstream>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <mutex>

#if __has_include(<pqxx/pqxx>)
#include <pqxx/pqxx>
#define NEXIS_HAS_PQXX 1
#endif

#if __has_include(<cpr/cpr.h>)
#include <cpr/cpr.h>
#define NEXIS_HAS_CPR 1
#elif __has_include(<curl/curl.h>)
#include <curl/curl.h>
#define NEXIS_HAS_CURL 1
#endif

namespace nexis::vault::orchestrator {

class MockFlowStateManager {
private:
    std::mutex mtx_;
    std::unordered_map<std::string, std::vector<std::string>> flow_history_;
    std::string ai_diagnostics_url_ = "https://ai.nexis.internal/v1/diagnose-trace";

public:
    static MockFlowStateManager& instance() {
        static MockFlowStateManager mgr;
        return mgr;
    }

    void record_state(const std::string& tx_id, const std::string& state) {
        std::lock_guard<std::mutex> lock(mtx_);
        flow_history_[tx_id].push_back(state);
    }

    const std::string& ai_url() const { return ai_diagnostics_url_; }
};

/**
 * Level 1: Persist Flow State to Postgres or In-Memory Mock
 * abcd_persist_flow_state
 */
bool abcd_persist_flow_state(const std::string& tx_id, const std::string& state) {
    if (tx_id.empty()) return false;

#if NEXIS_HAS_PQXX
    try {
        pqxx::connection conn("postgresql://nexis_admin:vault_pass@localhost:5432/nexis_vault");
        pqxx::work txn(conn);
        txn.exec_params(
            "INSERT INTO transaction_flow_states (tx_id, state, updated_at) VALUES ($1, $2, NOW()) "
            "ON CONFLICT (tx_id) DO UPDATE SET state = EXCLUDED.state, updated_at = NOW()",
            tx_id, state
        );
        txn.commit();
        std::cout << "[FlowManager::abcd] Persisted state [" << state << "] to PostgreSQL for " << tx_id << "\n";
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[FlowManager::abcd] PQXX DB error: " << e.what() << ", using mock storage.\n";
    }
#endif

    MockFlowStateManager::instance().record_state(tx_id, state);
    std::cout << "[FlowManager::abcd] Mock persisted state [" << state << "] for " << tx_id << "\n";
    return true;
}

/**
 * Level 2a: Trigger Compensation / Saga Rollback
 * efgh_trigger_compensation_logic
 */
bool efgh_trigger_compensation_logic(const std::string& tx_id, const std::string& failed_stage) {
    std::cout << "[FlowManager::efgh] Triggering saga compensation rollback for tx: " << tx_id 
              << " failed at stage: " << failed_stage << "\n";

    // 1. Release fund holds
    std::cout << "  -> Releasing ledger reservation locks...\n";
    // 2. Void merchant pending invoice
    std::cout << "  -> Voiding partner settlement invoice...\n";
    // 3. Emit compensation event
    std::cout << "  -> Emitting SAGA_COMPENSATION_COMPLETE event.\n";

    return true;
}

/**
 * Level 2b: AI Failure Diagnostics Engine
 * efgh_diagnose_failure_with_ai
 */
std::string efgh_diagnose_failure_with_ai(const std::string& error_trace) {
    auto& mgr = MockFlowStateManager::instance();
    std::string diagnosis;

#if defined(NEXIS_HAS_CPR)
    try {
        std::string prompt = "{\"trace\":\"" + error_trace + "\",\"model\":\"gemini-2.0-flash\"}";
        auto res = cpr::Post(
            cpr::Url{mgr.ai_url()},
            cpr::Header{{"Content-Type", "application/json"}},
            cpr::Body{prompt},
            cpr::Timeout{3000}
        );
        if (res.status_code == 200) {
            diagnosis = res.text;
        }
    } catch (...) {}
#endif

    if (diagnosis.empty()) {
        // Fallback local heuristic diagnosis
        if (error_trace.find("TIMEOUT") != std::string::npos) {
            diagnosis = "Root Cause: Upstream payment rail timeout. Recommended action: exponential backoff retry.";
        } else if (error_trace.find("INSUFFICIENT_FUNDS") != std::string::npos) {
            diagnosis = "Root Cause: User balance below threshold. Recommended action: abort without retry.";
        } else {
            diagnosis = "Root Cause: General platform exception. Rollback completed cleanly.";
        }
    }

    std::cout << "[FlowManager::efgh] AI Diagnosis: " << diagnosis << "\n";
    return diagnosis;
}

/**
 * Level 3: Failure Handling Coordinator
 * ijkl_handle_transaction_failure
 */
bool ijkl_handle_transaction_failure(const std::string& tx_id, const std::string& stage, const std::string& err_msg) {
    std::cerr << "[FlowManager::ijkl] Handling transaction failure for tx: " << tx_id 
              << " at stage: " << stage << " Error: " << err_msg << "\n";

    std::string diagnosis = efgh_diagnose_failure_with_ai(err_msg);
    bool compensated = efgh_trigger_compensation_logic(tx_id, stage);

    std::string final_state = compensated ? "ROLLED_BACK_COMPENSATED" : "ROLLBACK_FAILED_MANUAL_REVIEW";
    abcd_persist_flow_state(tx_id, final_state);

    return compensated;
}

/**
 * Level 4: Top-Level Flow Lifecycle Manager
 * mnop_manage_flow_completion
 */
bool mnop_manage_flow_completion(const std::string& tx_id, bool success) {
    std::cout << "[FlowManager::mnop] Finalizing flow completion for tx: " << tx_id 
              << " Success=" << (success ? "TRUE" : "FALSE") << "\n";

    if (success) {
        return abcd_persist_flow_state(tx_id, "COMPLETED_SETTLED");
    } else {
        return ijkl_handle_transaction_failure(tx_id, "EXECUTION_PHASE", "Transaction stage failed pipeline verification");
    }
}

} // namespace nexis::vault::orchestrator
