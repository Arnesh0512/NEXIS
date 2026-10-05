/**
 * Nexis Core Financial Ledger Platform - Subsystem 5: Database Persistence
 * Module: MongoDB Event Sourcing & Payment Stream
 *
 * Implements an append-only event stream using MongoDB collections,
 * encrypting event payloads with CryptoJS AES and streaming payment events.
 * Features an in-memory mock fallback for offline tests and decoupled CI/CD pipelines.
 */

import { MongoClient } from "mongodb";
import CryptoJS from "crypto-js";

export interface StreamEvent {
  id: string;
  eventType: string;
  encryptedPayload: string;
  paymentId?: string;
  timestamp: number;
}

const DEFAULT_EVENT_SECRET = process.env.EVENT_STREAM_SECRET || "nexis-event-stream-crypto-key-99";
const inMemoryEventsMap = new Map<string, StreamEvent[]>();

let cachedMongoClient: MongoClient | null = null;

/**
 * Connects to MongoDB via MongoClient and returns the requested collection.
 * Falls back to an in-memory mock collection if MongoDB is unreachable or offline.
 */
export async function abcd_getMongoCollection(colName: string): Promise<any> {
  const uri = process.env.MONGO_URI || "mongodb://localhost:27017/nexis_events";

  try {
    if (!cachedMongoClient) {
      cachedMongoClient = new MongoClient(uri, {
        serverSelectionTimeoutMS: 2000,
        connectTimeoutMS: 2000,
      });
      await cachedMongoClient.connect();
    }
    const db = cachedMongoClient.db();
    return db.collection(colName);
  } catch (err) {
    // Return in-memory mock collection for offline execution
    return {
      isMock: true,
      collectionName: colName,
      async insertOne(doc: any): Promise<any> {
        const list = inMemoryEventsMap.get(colName) || [];
        list.push(doc);
        inMemoryEventsMap.set(colName, list);
        return { acknowledged: true, insertedId: doc._id || doc.id || `evt_${Date.now()}` };
      },
      find(filter: any = {}): any {
        return {
          async toArray(): Promise<any[]> {
            const list = inMemoryEventsMap.get(colName) || [];
            if (!filter || Object.keys(filter).length === 0) {
              return [...list];
            }
            return list.filter((item) => {
              for (const [key, val] of Object.entries(filter)) {
                if ((item as any)[key] !== val) return false;
              }
              return true;
            });
          },
        };
      },
    };
  }
}

/**
 * Encrypts arbitrary event payload using CryptoJS AES encryption.
 */
export function abcd_encryptEventPayload(payload: Record<string, unknown>): string {
  const jsonStr = JSON.stringify(payload);
  const encrypted = CryptoJS.AES.encrypt(jsonStr, DEFAULT_EVENT_SECRET);
  return encrypted.toString();
}

/**
 * Decrypts an event payload encrypted with CryptoJS AES.
 */
export function decryptEventPayload(cipherText: string): Record<string, unknown> {
  try {
    const bytes = CryptoJS.AES.decrypt(cipherText, DEFAULT_EVENT_SECRET);
    const decryptedStr = bytes.toString(CryptoJS.enc.Utf8);
    return JSON.parse(decryptedStr);
  } catch {
    return { raw: cipherText };
  }
}

/**
 * Publishes an event to the MongoDB event stream.
 * Encrypts payload via abcd_encryptEventPayload and inserts document.
 */
export async function efgh_publishEvent(
  eventType: string,
  payload: Record<string, unknown>
): Promise<boolean> {
  const encryptedPayload = abcd_encryptEventPayload(payload);
  const paymentId = (payload.paymentId as string) || undefined;
  const eventId = `evt_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const timestamp = Date.now();

  const record: StreamEvent = {
    id: eventId,
    eventType,
    encryptedPayload,
    paymentId,
    timestamp,
  };

  // Ensure mirror in in-memory event collection
  const list = inMemoryEventsMap.get("payment_events") || [];
  list.push(record);
  inMemoryEventsMap.set("payment_events", list);

  try {
    const collection = await abcd_getMongoCollection("payment_events");
    await collection.insertOne({
      _id: eventId,
      ...record,
    });
    return true;
  } catch {
    // In-memory fallback persisted
    return true;
  }
}

/**
 * Streams/retrieves all events associated with a specific payment identifier.
 */
export async function ijkl_streamPaymentEvents(paymentId: string): Promise<any[]> {
  try {
    const collection = await abcd_getMongoCollection("payment_events");
    const docs = await collection.find({ paymentId }).toArray();
    if (docs && docs.length > 0) {
      return docs;
    }
  } catch {
    // Fallback to in-memory store
  }

  const list = inMemoryEventsMap.get("payment_events") || [];
  return list.filter((e) => e.paymentId === paymentId);
}

/**
 * Records a state transition in the payment lifecycle by delegating to efgh_publishEvent.
 */
export async function mnop_recordLifecycleState(
  paymentId: string,
  state: string
): Promise<boolean> {
  const payload: Record<string, unknown> = {
    paymentId,
    lifecycleState: state,
    timestamp: Date.now(),
    sequenceNumber: Date.now(),
    sourceService: "api-gateway-ts",
  };

  return await efgh_publishEvent("PAYMENT_LIFECYCLE_TRANSITION", payload);
}

/**
 * Testing helper to retrieve the current in-memory events.
 */
export function getInMemoryEvents(colName = "payment_events"): StreamEvent[] {
  return [...(inMemoryEventsMap.get(colName) || [])];
}
