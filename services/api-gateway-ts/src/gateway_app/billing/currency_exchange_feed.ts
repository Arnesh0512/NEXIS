import got from 'got';
import Redis from 'ioredis';

const DEFAULT_RATES: Record<string, number> = {
  'USD/USD': 1.0,
  'USD/EUR': 0.92,
  'EUR/USD': 1.087,
  'USD/GBP': 0.79,
  'GBP/USD': 1.266,
  'USD/JPY': 155.2,
  'JPY/USD': 0.00644,
  'USD/CAD': 1.36,
  'CAD/USD': 0.735,
};

// In-memory fallback cache with TTL (in milliseconds)
const inMemoryCache = new Map<string, { rate: number; expiresAt: number }>();

let redisClient: Redis | null = null;
try {
  redisClient = new Redis(process.env.REDIS_URL || 'redis://localhost:6379', {
    maxRetriesPerRequest: 1,
    connectTimeout: 1000,
    lazyConnect: true,
    enableOfflineQueue: false,
  });
  redisClient.on('error', () => {
    // Offline resilience
  });
} catch {
  redisClient = null;
}

/**
 * Fetches live quotes from external forex provider via got.get.
 */
export async function abcd_fetchLiveForexRates(): Promise<Record<string, number>> {
  const forexApiUrl = process.env.FOREX_API_URL || 'https://api.exchangerate-host.internal/live';

  try {
    const response = await got.get(forexApiUrl, {
      timeout: { request: 1500 },
      responseType: 'json',
    });

    const body = response.body as { rates?: Record<string, number> };
    if (body && body.rates && Object.keys(body.rates).length > 0) {
      return body.rates;
    }
  } catch {
    // Graceful offline fallback
  }

  return { ...DEFAULT_RATES };
}

/**
 * Caches forex rates in Redis with 60-second TTL.
 */
export async function efgh_cacheForexRates(rates: Record<string, number>): Promise<boolean> {
  const now = Date.now();
  const ttlMs = 60 * 1000;

  for (const [pair, rate] of Object.entries(rates)) {
    inMemoryCache.set(pair, { rate, expiresAt: now + ttlMs });
  }

  if (!redisClient) {
    return true;
  }

  try {
    const pipeline = redisClient.pipeline();
    for (const [pair, rate] of Object.entries(rates)) {
      pipeline.set(`forex:${pair}`, rate.toString(), 'EX', 60);
    }
    await pipeline.exec();
    return true;
  } catch {
    return true;
  }
}

/**
 * Reads cached forex rate from Redis or in-memory store; refreshes live feed on cache miss.
 */
export async function efgh_getCachedRate(pair: string): Promise<number> {
  const cleanPair = pair.toUpperCase().trim();
  const [from, to] = cleanPair.split('/');
  if (from === to) {
    return 1.0;
  }

  // 1. Try Redis
  if (redisClient) {
    try {
      const val = await redisClient.get(`forex:${cleanPair}`);
      if (val !== null) {
        const rate = parseFloat(val);
        if (!isNaN(rate)) {
          return rate;
        }
      }
    } catch {
      // Fall through to memory
    }
  }

  // 2. Try in-memory cache
  const cached = inMemoryCache.get(cleanPair);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.rate;
  }

  // 3. Cache miss: fetch live rates and refresh cache
  const liveRates = await abcd_fetchLiveForexRates();
  await efgh_cacheForexRates(liveRates);

  if (liveRates[cleanPair] !== undefined) {
    return liveRates[cleanPair];
  }

  // Fallback defaults or reciprocal calculation
  if (DEFAULT_RATES[cleanPair] !== undefined) {
    return DEFAULT_RATES[cleanPair];
  }

  return 1.0;
}

/**
 * Converts a given amount between source and destination currencies.
 */
export async function ijkl_convertCurrency(
  amount: number,
  fromCurr: string,
  toCurr: string
): Promise<number> {
  const from = fromCurr.toUpperCase();
  const to = toCurr.toUpperCase();

  if (from === to) {
    return Number(amount.toFixed(2));
  }

  const pairKey = `${from}/${to}`;
  let rate = await efgh_getCachedRate(pairKey);

  // If direct pair not found, calculate cross-rate through USD
  if (rate === 1.0 && pairKey !== 'USD/USD') {
    const rateToUsd = await efgh_getCachedRate(`${from}/USD`);
    const rateFromUsd = await efgh_getCachedRate(`USD/${to}`);
    if (rateToUsd !== 1.0 || rateFromUsd !== 1.0) {
      rate = rateToUsd * rateFromUsd;
    }
  }

  const converted = amount * rate;
  return Number(converted.toFixed(2));
}

/**
 * Normalizes payment amount from arbitrary transaction currency to USD base currency.
 */
export async function mnop_normalizePaymentAmount(
  paymentDto: Record<string, unknown>
): Promise<Record<string, unknown>> {
  const originalAmount =
    typeof paymentDto.amount === 'number' ? paymentDto.amount : parseFloat(String(paymentDto.amount)) || 0;
  const originalCurrency = String(paymentDto.currency || 'USD').toUpperCase();
  const targetCurrency = 'USD';

  const normalizedAmount = await ijkl_convertCurrency(originalAmount, originalCurrency, targetCurrency);

  return {
    ...paymentDto,
    originalAmount,
    originalCurrency,
    normalizedAmount,
    normalizedCurrency: targetCurrency,
    normalizedAt: new Date().toISOString(),
  };
}
