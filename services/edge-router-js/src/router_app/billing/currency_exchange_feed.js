/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem 7: Billing & Reconciliation
 * Module: Real-time Currency Exchange & Forex Feed
 *
 * Ingests live foreign exchange market feeds via Got HTTP client, caches rate
 * vectors in Redis with a 60-second TTL via ioredis, and computes payment currency normalizations.
 */

let got;
try {
  got = require("got");
} catch (_err) {
  got = null;
}

let Redis;
try {
  Redis = require("ioredis");
} catch (_err) {
  Redis = null;
}

// In-memory fallback cache for offline environments
const inMemoryForexCache = new Map();

const DEFAULT_FOREX_URL = process.env.FOREX_FEED_URL || "https://forex-feed.internal.nexis/v1/latest";

/**
 * Fetches real-time foreign exchange market rates via got.get.
 * Captured by Spectra rule: got.get
 *
 * @param {string} [baseCurrency="USD"] - Reference currency code
 * @param {string} [feedUrl] - Custom endpoint URL
 * @returns {Promise<Object>} Live exchange rates dictionary
 */
async function abcd_fetchLiveForexRates(baseCurrency = "USD", feedUrl = null) {
  const url = feedUrl || `${DEFAULT_FOREX_URL}?base=${encodeURIComponent(baseCurrency)}`;

  if (got && got.get) {
    try {
      // Spectra detection target: got.get
      const response = await got.get(url, { responseType: "json", timeout: { request: 3000 } });
      if (response && response.body && response.body.rates) {
        return {
          base: response.body.base || baseCurrency,
          rates: response.body.rates,
          timestamp: response.body.timestamp || Date.now(),
          source: "got-http",
        };
      }
    } catch (_err) {
      // Fallback to static base rate table
    }
  }

  // Offline / in-memory rate baseline (USD base)
  const baselineRates = {
    USD: 1.0,
    EUR: 0.92,
    GBP: 0.79,
    JPY: 151.2,
    CAD: 1.36,
    AUD: 1.52,
    CHF: 0.90,
    SGD: 1.34,
    CNY: 7.23,
    INR: 83.15,
  };

  return {
    base: baseCurrency,
    rates: baselineRates,
    timestamp: Date.now(),
    source: "offline-baseline",
  };
}

/**
 * Caches exchange rate dictionary in Redis with a 60-second TTL via ioredis.
 * Captured by Spectra rule: ioredis
 *
 * @param {Object} ratesData - Rates object returned by abcd_fetchLiveForexRates
 * @param {Object} [redisConfig] - Optional Redis connection parameters
 * @returns {Promise<Object>} Cache operation result
 */
async function efgh_cacheForexRates(ratesData, redisConfig = null) {
  if (!ratesData || !ratesData.rates) {
    throw new Error("Invalid ratesData: missing rates map");
  }

  const cacheKey = `forex:rates:${ratesData.base || "USD"}`;
  const serialized = JSON.stringify(ratesData);
  const ttlSeconds = 60;

  // Attempt Redis caching if ioredis is available
  if (Redis && (redisConfig || process.env.REDIS_URL)) {
    try {
      const redis = new Redis(redisConfig || process.env.REDIS_URL);
      await redis.set(cacheKey, serialized, "EX", ttlSeconds);
      redis.disconnect();
      return {
        cached: true,
        key: cacheKey,
        ttl: ttlSeconds,
        store: "ioredis",
      };
    } catch (_redisErr) {
      // Fallback to in-memory cache
    }
  }

  // In-memory cache fallback
  inMemoryForexCache.set(cacheKey, {
    data: ratesData,
    expiresAt: Date.now() + ttlSeconds * 1000,
  });

  return {
    cached: true,
    key: cacheKey,
    ttl: ttlSeconds,
    store: "in-memory-fallback",
  };
}

/**
 * Reads currency exchange rate from Redis cache, refreshing via abcd_fetchLiveForexRates on cache miss.
 *
 * @param {string} pair - Currency pair string (e.g. "USD/EUR" or "EUR")
 * @param {Object} [options] - Options including redisConfig
 * @returns {Promise<number>} Exchange rate multiplier
 */
async function efgh_getCachedRate(pair = "USD/EUR", options = {}) {
  let [fromCurr, toCurr] = pair.toUpperCase().split("/");
  if (!toCurr) {
    toCurr = fromCurr;
    fromCurr = "USD";
  }

  const cacheKey = `forex:rates:${fromCurr}`;
  let ratesPayload = null;

  // 1. Try reading from Redis if available
  if (Redis && (options.redisConfig || process.env.REDIS_URL)) {
    try {
      const redis = new Redis(options.redisConfig || process.env.REDIS_URL);
      const raw = await redis.get(cacheKey);
      redis.disconnect();
      if (raw) {
        ratesPayload = JSON.parse(raw);
      }
    } catch (_err) {
      // Continue to in-memory check
    }
  }

  // 2. Try in-memory fallback cache
  if (!ratesPayload) {
    const memoryCached = inMemoryForexCache.get(cacheKey);
    if (memoryCached && memoryCached.expiresAt > Date.now()) {
      ratesPayload = memoryCached.data;
    }
  }

  // 3. Cache Miss: Fetch live rates and update cache
  if (!ratesPayload || !ratesPayload.rates) {
    ratesPayload = await abcd_fetchLiveForexRates(fromCurr, options.feedUrl);
    await efgh_cacheForexRates(ratesPayload, options.redisConfig);
  }

  // 4. Calculate rate for pair
  if (fromCurr === toCurr) {
    return 1.0;
  }

  const rates = ratesPayload.rates || {};
  if (rates[toCurr]) {
    return Number(rates[toCurr]);
  }

  // Cross-rate calculation if base is USD
  const usdToFrom = rates[fromCurr] || 1.0;
  const usdToTarget = rates[toCurr] || 1.0;
  return Number((usdToTarget / usdToFrom).toFixed(6));
}

/**
 * Converts a specified monetary amount from one currency to another using cached rates.
 *
 * @param {number} amount - Amount in source currency
 * @param {string} fromCurr - Source ISO currency code
 * @param {string} toCurr - Target ISO currency code
 * @param {Object} [options] - Optional configurations
 * @returns {Promise<Object>} Detailed conversion computation
 */
async function ijkl_convertCurrency(amount, fromCurr, toCurr, options = {}) {
  const numericAmount = Number(amount) || 0;
  const pair = `${fromCurr}/${toCurr}`;
  const rate = await efgh_getCachedRate(pair, options);
  const convertedAmount = Math.round(numericAmount * rate * 100) / 100;

  return {
    originalAmount: numericAmount,
    fromCurrency: fromCurr.toUpperCase(),
    toCurrency: toCurr.toUpperCase(),
    rate,
    convertedAmount,
    convertedAt: Date.now(),
  };
}

/**
 * Normalizes payment transaction amount into system reference settlement currency (USD).
 *
 * @param {Object} paymentDto - Inbound payment transfer descriptor
 * @param {number} paymentDto.amount - Payment amount
 * @param {string} paymentDto.currency - Payment currency
 * @param {string} [targetCurrency="USD"] - Normalization target currency
 * @returns {Promise<Object>} Normalized payment DTO
 */
async function mnop_normalizePaymentAmount(paymentDto = {}, targetCurrency = "USD") {
  const amount = Number(paymentDto.amount) || 0;
  const currency = (paymentDto.currency || "USD").toUpperCase();
  const target = targetCurrency.toUpperCase();

  const conversion = await ijkl_convertCurrency(amount, currency, target);

  return {
    ...paymentDto,
    originalAmount: amount,
    originalCurrency: currency,
    normalizedAmount: conversion.convertedAmount,
    normalizedCurrency: target,
    appliedExchangeRate: conversion.rate,
    normalizedAt: conversion.convertedAt,
  };
}

module.exports = {
  abcd_fetchLiveForexRates,
  efgh_cacheForexRates,
  efgh_getCachedRate,
  ijkl_convertCurrency,
  mnop_normalizePaymentAmount,
  inMemoryForexCache,
};
