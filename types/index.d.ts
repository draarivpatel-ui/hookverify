/**
 * Types for hookverify. No external type dependencies.
 * The runtime uses only node:crypto from the Node standard library.
 */

/** Error codes exposed as `error.code` on every HookVerifyError. */
export type ErrorCode =
  | 'INVALID_ARGUMENT'
  | 'INVALID_BODY'
  | 'MISSING_HEADER'
  | 'INVALID_HEADER'
  | 'INVALID_SECRET'
  | 'INVALID_SIGNATURE'
  | 'SIGNATURE_MISMATCH'
  | 'TIMESTAMP_MISSING'
  | 'TIMESTAMP_INVALID'
  | 'TIMESTAMP_OUT_OF_TOLERANCE'
  | 'REPLAYED_DELIVERY'
  | 'UNKNOWN_PROVIDER'
  | 'PROVIDER_ERROR';

export declare const ERROR_CODES: Readonly<Record<ErrorCode, ErrorCode>>;

/** Every rejection thrown by this library is a HookVerifyError with a stable code. */
export declare class HookVerifyError extends Error {
  readonly name: 'HookVerifyError';
  readonly code: ErrorCode;
  readonly details?: Readonly<Record<string, unknown>>;
  constructor(code: ErrorCode, message: string, details?: Record<string, unknown>);
  toJSON(): Record<string, unknown>;
}

/** Byte-exact raw payload. Parsed objects are rejected at runtime. */
export type RawBody = Buffer | Uint8Array | string;

/** Header value: a single string or a homogeneous array of strings. */
export type HeaderValue = string | ReadonlyArray<string> | null;
export type HeaderMap =
  | Readonly<Record<string, HeaderValue>>
  | Map<string, HeaderValue>
  | { get(name: string): unknown; forEach(callback: (value: unknown, key: string) => void): void };

/** Milliseconds since the Unix epoch. */
export type Milliseconds = number;

/** A synchronous or asynchronous replay store. Keys are opaque provider-scoped strings. */
export interface ReplayStore {
  checkAndRecord(key: string, nowMs: Milliseconds): boolean | Promise<boolean>;
  has?(key: string, nowMs?: Milliseconds): boolean;
  prune?(nowMs?: Milliseconds): number;
  clear?(): void;
  readonly size?: number;
}

export interface ProviderContext {
  readonly provider: string;
  readonly body: Buffer;
  readonly headers: ReadonlyMap<string, ReadonlyArray<string | null>>;
  readonly secrets: readonly string[];
  readonly toleranceSeconds: number;
  readonly nowMs: Milliseconds;
  readonly options: Readonly<Record<string, unknown>>;
  readonly helpers: {
    decodeHex(value: string, label?: string): Buffer;
    decodeBase64(value: string, label?: string): Buffer;
    decodeHexOfLength(value: string, bytes: number, label?: string): Buffer;
    constantTimeEqual(a: Buffer, b: Buffer): boolean;
    hmac(secret: string | Buffer, payload: Buffer, algorithm?: string): Buffer;
    deliveryKey(provider: string, identifier: string): string;
    signatureKey(provider: string, secretIndex: number, signature: Buffer | Uint8Array): string;
    getHeader(ctx: ProviderContext, name: string): string;
    getOptionalHeader(ctx: ProviderContext, name: string): string | null;
    parseTimestampSeconds(value: string): Milliseconds;
    verifyHmac(ctx: ProviderContext, provided: Buffer | Buffer[], payload?: Buffer): VerificationResultInternal;
    verifyHmacWithSecrets(secrets: ReadonlyArray<string | Buffer>, provided: Buffer | Buffer[], payload: Buffer): VerificationResultInternal;
    fail(code: ErrorCode, message: string, details?: Record<string, unknown>): never;
    HookVerifyError: typeof HookVerifyError;
  };
}

/** Internal result contract for provider authors. */
export interface VerificationResultInternal {
  timestampMs?: Milliseconds | null;
  secretIndex?: number;
  signature?: Buffer;
  replayKey?: string;
}

/** Public, frozen result returned by successful verification. */
export interface VerificationResult {
  readonly provider: string;
  readonly valid: true;
  readonly timestamp: Date | null;
  readonly secretIndex: number | null;
  readonly replayKey: string;
}

export interface VerifyOptions {
  /** Primary shared secret. Ignored when `secrets` is provided. */
  secret?: string;
  /** Ordered secrets for zero-downtime rotation. */
  secrets?: readonly string[];
  /** Replay window in seconds, default 300. Applies to both stale and future timestamps. */
  toleranceSeconds?: number;
  /** Injectable clock for deterministic tests; returns milliseconds. */
  now?: () => Milliseconds;
  /** Optional replay store; callers can supply a Redis-backed implementation. */
  replayStore?: ReplayStore;
  /** Provider-specific options, for example `publicKey` for Discord. */
  [key: string]: unknown;
}

export interface ProviderDefinition {
  readonly name: string;
  readonly description?: string;
  readonly requiredHeaders?: readonly string[];
  verify(ctx: ProviderContext): VerificationResultInternal;
}

export interface Provider extends ProviderDefinition {
  readonly name: string;
  readonly description: string;
  readonly requiredHeaders: ReadonlyArray<string>;
}

/** Bounded LRU + TTL in-memory replay store. */
export declare class MemoryReplayStore implements ReplayStore {
  constructor(options?: { maxEntries?: number; ttlSeconds?: number });
  readonly maxEntries: number;
  readonly ttlSeconds: number;
  readonly size: number;
  checkAndRecord(key: string, nowMs?: Milliseconds): boolean;
  has(key: string, nowMs?: Milliseconds): boolean;
  prune(nowMs?: Milliseconds): number;
  clear(): void;
}

export declare function defineProvider(definition: ProviderDefinition): Provider;
export declare function registerProvider(provider: Provider): Provider;
export declare function getProvider(name: string): Provider;
export declare function listProviders(): ReadonlyArray<string>;

export declare function verify(
  provider: string | Provider,
  body: RawBody,
  headers: HeaderMap,
  options?: VerifyOptions
): VerificationResult;

export declare function verify(
  options: VerifyOptions & {
    provider: string | Provider;
    body: RawBody;
    headers: HeaderMap;
  }
): VerificationResult;

export declare function verifyAsync(
  provider: string | Provider,
  body: RawBody,
  headers: HeaderMap,
  options?: VerifyOptions
): Promise<VerificationResult>;

export declare function verifyAsync(
  options: VerifyOptions & {
    provider: string | Provider;
    body: RawBody;
    headers: HeaderMap;
  }
): Promise<VerificationResult>;

export declare function isValid(
  provider: string | Provider,
  body: RawBody,
  headers: HeaderMap,
  options?: VerifyOptions
): boolean;

export declare function isValid(
  options: VerifyOptions & {
    provider: string | Provider;
    body: RawBody;
    headers: HeaderMap;
  }
): boolean;

export interface Verifier {
  verify(provider: string | Provider, body: RawBody, headers: HeaderMap, overrides?: VerifyOptions): VerificationResult;
  verifyAsync(provider: string | Provider, body: RawBody, headers: HeaderMap, overrides?: VerifyOptions): Promise<VerificationResult>;
  isValid(provider: string | Provider, body: RawBody, headers: HeaderMap, overrides?: VerifyOptions): boolean;
}

export declare function createVerifier(defaults?: VerifyOptions): Verifier;

export declare const providers: Readonly<{
  github: Provider;
  stripe: Provider;
  slack: Provider;
  shopify: Provider;
  linear: Provider;
  svix: Provider;
  standardWebhooks: Provider;
  discord: Provider;
}>;

export declare const github: Provider;
export declare const stripe: Provider;
export declare const slack: Provider;
export declare const shopify: Provider;
export declare const linear: Provider;
export declare const svix: Provider;
export declare const standardWebhooks: Provider;
export declare const discord: Provider;

export declare const helpers: Readonly<{
  decodeHex(value: string, label?: string): Buffer;
  decodeBase64(value: string, label?: string): Buffer;
  constantTimeEqual(a: Buffer, b: Buffer): boolean;
  deliveryKey(provider: string, identifier: string): string;
  normalizeBody(body: unknown): Buffer;
  normalizeHeaders(headers: unknown): Map<string, string[]>;
  parseTimestampSeconds(value: string): Milliseconds;
}>;

declare const hookverify: {
  HookVerifyError: typeof HookVerifyError;
  ERROR_CODES: typeof ERROR_CODES;
  MemoryReplayStore: typeof MemoryReplayStore;
  defineProvider: typeof defineProvider;
  registerProvider: typeof registerProvider;
  getProvider: typeof getProvider;
  listProviders: typeof listProviders;
  verify: typeof verify;
  verifyAsync: typeof verifyAsync;
  isValid: typeof isValid;
  createVerifier: typeof createVerifier;
  providers: typeof providers;
  github: typeof github;
  stripe: typeof stripe;
  slack: typeof slack;
  shopify: typeof shopify;
  linear: typeof linear;
  svix: typeof svix;
  standardWebhooks: typeof standardWebhooks;
  discord: typeof discord;
  helpers: typeof helpers;
};

export default hookverify;
