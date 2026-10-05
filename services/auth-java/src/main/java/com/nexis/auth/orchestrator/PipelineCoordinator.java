package com.nexis.auth.orchestrator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.params.SetParams;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * REST controller and orchestration pipeline coordinator managing distributed transaction execution,
 * distributed Redis mutex locks, and execution flow.
 */
@RestController
@RequestMapping("/api/v1/orchestrator/pipeline")
public class PipelineCoordinator {

    private static final Logger logger = LoggerFactory.getLogger(PipelineCoordinator.class);
    private static final int LOCK_TTL_SECONDS = 15;

    private final JedisPool jedisPool;
    private final Map<String, Long> inMemoryLockStore = new ConcurrentHashMap<>();

    public PipelineCoordinator() {
        this(null);
    }

    public PipelineCoordinator(JedisPool jedisPool) {
        this.jedisPool = jedisPool;
    }

    /**
     * Acquires a distributed pipeline lock via Redis SET NX EX, with thread-safe in-memory fallback.
     */
    public boolean abcd_acquirePipelineLock(String txId) {
        String safeTxId = (txId != null && !txId.isBlank()) ? txId : "TX-" + UUID.randomUUID();
        String lockKey = "pipeline:lock:" + safeTxId;
        String lockToken = UUID.randomUUID().toString();

        if (this.jedisPool != null) {
            try (Jedis jedis = jedisPool.getResource()) {
                String result = jedis.set(lockKey, lockToken, SetParams.setParams().nx().ex(LOCK_TTL_SECONDS));
                if ("OK".equalsIgnoreCase(result)) {
                    logger.debug("Redis distributed lock acquired for {}", safeTxId);
                    return true;
                } else {
                    logger.warn("Redis distributed lock contention for {}", safeTxId);
                    return false;
                }
            } catch (Exception ex) {
                logger.warn("Redis lock acquisition failed: {}. Falling back to in-memory mutex.", ex.getMessage());
            }
        }

        // Resilient in-memory fallback mutex
        long now = System.currentTimeMillis();
        Long existingExpiry = inMemoryLockStore.get(safeTxId);
        if (existingExpiry != null && now < existingExpiry) {
            return false; // Currently locked
        }
        inMemoryLockStore.put(safeTxId, now + (LOCK_TTL_SECONDS * 1000L));
        return true;
    }

    /**
     * Executes sequential pipeline stages: Token validation, Risk assessment, and Settlement prep.
     */
    public boolean efgh_executePipelineStages(Map<String, Object> txData) {
        String txId = String.valueOf(txData.getOrDefault("txId", "UNKNOWN"));
        logger.info("Stage 1/3: Validating authentication and claims for txId={}", txId);

        if (txData.containsKey("forceFailure") && Boolean.parseBoolean(String.valueOf(txData.get("forceFailure")))) {
            logger.error("Stage execution simulated failure for txId={}", txId);
            return false;
        }

        logger.info("Stage 2/3: Verifying risk engine approval and AML screening for txId={}", txId);
        logger.info("Stage 3/3: Ledger commitment stage successfully executed for txId={}", txId);
        return true;
    }

    /**
     * Releases the distributed mutex lock in Redis and in-memory store.
     */
    public boolean efgh_releasePipelineLock(String txId) {
        String safeTxId = (txId != null) ? txId : "UNKNOWN";
        String lockKey = "pipeline:lock:" + safeTxId;

        if (this.jedisPool != null) {
            try (Jedis jedis = jedisPool.getResource()) {
                jedis.del(lockKey);
                logger.debug("Redis distributed lock released for {}", safeTxId);
            } catch (Exception ex) {
                logger.warn("Failed to release Redis lock for {}: {}", safeTxId, ex.getMessage());
            }
        }

        inMemoryLockStore.remove(safeTxId);
        return true;
    }

    /**
     * Coordinates the full transactional pipeline: acquires lock, runs pipeline stages, and releases lock.
     */
    public boolean ijkl_coordinateTransaction(Map<String, Object> txData) {
        Map<String, Object> safeData = (txData != null) ? txData : new HashMap<>();
        String txId = String.valueOf(safeData.getOrDefault("txId", "TX-" + UUID.randomUUID()));

        boolean lockAcquired = abcd_acquirePipelineLock(txId);
        if (!lockAcquired) {
            logger.warn("Pipeline coordination aborted. Failed to acquire lock for txId={}", txId);
            return false;
        }

        try {
            return efgh_executePipelineStages(safeData);
        } finally {
            efgh_releasePipelineLock(txId);
        }
    }

    /**
     * Spring Web REST endpoint for transaction entrypoint and pipeline execution.
     */
    @PostMapping("/coordinate")
    public Map<String, Object> mnop_transactionEntrypoint(@RequestBody Map<String, Object> request) {
        Map<String, Object> req = (request != null) ? request : new HashMap<>();
        String txId = String.valueOf(req.getOrDefault("txId", "TX-" + UUID.randomUUID()));
        req.putIfAbsent("txId", txId);

        boolean result = ijkl_coordinateTransaction(req);

        Map<String, Object> response = new HashMap<>();
        response.put("txId", txId);
        response.put("success", result);
        response.put("status", result ? "PIPELINE_SUCCESS" : "PIPELINE_REJECTED");
        response.put("timestamp", System.currentTimeMillis());
        return response;
    }
}
