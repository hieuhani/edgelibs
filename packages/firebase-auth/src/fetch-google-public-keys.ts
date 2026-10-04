import { PublicKeysFetchError } from "./error";
import type { KeyLike } from "jose";

const GOOGLE_PUBLIC_KEYS_URL =
  "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";

// Used when Google's response has no usable max-age.
const DEFAULT_MAX_AGE_SECONDS = 60 * 60;

export type PublicKeys = Record<string, string>;

/** Keys by `kid`: a PEM X.509 certificate, as Google publishes it, or an imported key. */
export type VerificationKeys = Record<string, string | KeyLike>;

export type PublicKeysFetcher = (options?: {
  forceRefresh?: boolean;
}) => Promise<VerificationKeys>;

type CachedPublicKeys = { keys: PublicKeys; expiresAt: number };

let cached: CachedPublicKeys | undefined;
let inflight: Promise<CachedPublicKeys> | undefined;

const parseMaxAge = (cacheControl: string | null): number => {
  const match = cacheControl?.match(/max-age=(\d+)/);
  return match ? Number(match[1]) : DEFAULT_MAX_AGE_SECONDS;
};

const requestGooglePublicKeys = async (): Promise<CachedPublicKeys> => {
  let response: Response;
  try {
    response = await fetch(GOOGLE_PUBLIC_KEYS_URL);
  } catch (e) {
    throw new PublicKeysFetchError(`failed to fetch Google public keys: ${(e as Error).message}`);
  }
  if (!response.ok) {
    throw new PublicKeysFetchError(
      `failed to fetch Google public keys: HTTP ${response.status}`,
      response.status,
    );
  }
  const keys = (await response.json()) as PublicKeys;
  const maxAge = parseMaxAge(response.headers.get("Cache-Control"));
  return { keys, expiresAt: Date.now() + maxAge * 1000 };
};

/**
 * Fetches Google's current public keys without caching.
 *
 * Prefer `getGooglePublicKeys`, which caches the keys for as long as Google's
 * `Cache-Control: max-age` allows.
 */
export const fetchGooglePublicKeys = async (): Promise<PublicKeys> => {
  const { keys } = await requestGooglePublicKeys();
  return keys;
};

/**
 * Returns Google's public keys, cached in module scope until the `max-age` that
 * Google sends expires. Concurrent callers share one request. Pass
 * `forceRefresh` when a token's `kid` is missing, because Google rotates keys.
 */
export const getGooglePublicKeys = async (options?: {
  forceRefresh?: boolean;
}): Promise<PublicKeys> => {
  if (!options?.forceRefresh && cached && cached.expiresAt > Date.now()) {
    return cached.keys;
  }
  if (!inflight) {
    inflight = requestGooglePublicKeys()
      .then((result) => {
        cached = result;
        return result;
      })
      .finally(() => {
        inflight = undefined;
      });
  }
  const { keys } = await inflight;
  return keys;
};

/** Clears the cache used by `getGooglePublicKeys`. Intended for tests. */
export const clearGooglePublicKeysCache = () => {
  cached = undefined;
  inflight = undefined;
};
