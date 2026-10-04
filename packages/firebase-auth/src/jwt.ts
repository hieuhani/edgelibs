import { JwtDecodeError } from "./error";
import type { JwtDecodeErrorCode } from "./error";
import { getGooglePublicKeys } from "./fetch-google-public-keys";
import type { PublicKeysFetcher, VerificationKeys } from "./fetch-google-public-keys";
import { decodeProtectedHeader, importX509, jwtVerify } from "jose";
import type { KeyLike } from "jose";

export interface DecodedIdToken {
  /**
   * The audience for which this token is intended.
   *
   * This value is a string equal to your Firebase project ID, the unique
   * identifier for your Firebase project, which can be found in [your project's
   * settings](https://console.firebase.google.com/project/_/settings/general/android:com.random.android).
   */
  aud: string;

  /**
   * Time, in seconds since the Unix epoch, when the end-user authentication
   * occurred.
   *
   * This value is not set when this particular ID token was created, but when the
   * user initially logged in to this session. In a single session, the Firebase
   * SDKs will refresh a user's ID tokens every hour. Each ID token will have a
   * different [`iat`](#iat) value, but the same `auth_time` value.
   */
  auth_time: number;

  /**
   * The email of the user to whom the ID token belongs, if available.
   */
  email?: string;

  /**
   * Whether or not the email of the user to whom the ID token belongs is
   * verified, provided the user has an email.
   */
  email_verified?: boolean;

  /**
   * The ID token's expiration time, in seconds since the Unix epoch. That is, the
   * time at which this ID token expires and should no longer be considered valid.
   *
   * The Firebase SDKs transparently refresh ID tokens every hour, issuing a new
   * ID token with up to a one hour expiration.
   */
  exp: number;

  /**
   * Information about the sign in event, including which sign in provider was
   * used and provider-specific identity details.
   *
   * This data is provided by the Firebase Authentication service and is a
   * reserved claim in the ID token.
   */
  firebase: {
    /**
     * Provider-specific identity details corresponding
     * to the provider used to sign in the user.
     */
    identities: {
      [key: string]: any;
    };

    /**
     * The ID of the provider used to sign in the user.
     * One of `"anonymous"`, `"password"`, `"facebook.com"`, `"github.com"`,
     * `"google.com"`, `"twitter.com"`, `"apple.com"`, `"microsoft.com"`,
     * `"yahoo.com"`, `"phone"`, `"playgames.google.com"`, `"gc.apple.com"`,
     * or `"custom"`.
     *
     * Additional Identity Platform provider IDs include `"linkedin.com"`,
     * OIDC and SAML identity providers prefixed with `"saml."` and `"oidc."`
     * respectively.
     */
    sign_in_provider: string;

    /**
     * The type identifier or `factorId` of the second factor, provided the
     * ID token was obtained from a multi-factor authenticated user.
     * For phone, this is `"phone"`.
     */
    sign_in_second_factor?: string;

    /**
     * The `uid` of the second factor used to sign in, provided the
     * ID token was obtained from a multi-factor authenticated user.
     */
    second_factor_identifier?: string;

    /**
     * The ID of the tenant the user belongs to, if available.
     */
    tenant?: string;
    [key: string]: any;
  };

  /**
   * The ID token's issued-at time, in seconds since the Unix epoch. That is, the
   * time at which this ID token was issued and should start to be considered
   * valid.
   *
   * The Firebase SDKs transparently refresh ID tokens every hour, issuing a new
   * ID token with a new issued-at time. If you want to get the time at which the
   * user session corresponding to the ID token initially occurred, see the
   * [`auth_time`](#auth_time) property.
   */
  iat: number;

  /**
   * The issuer identifier for the issuer of the response.
   *
   * This value is a URL with the format
   * `https://securetoken.google.com/<PROJECT_ID>`, where `<PROJECT_ID>` is the
   * same project ID specified in the [`aud`](#aud) property.
   */
  iss: string;

  /**
   * The phone number of the user to whom the ID token belongs, if available.
   */
  phone_number?: string;

  /**
   * The photo URL for the user to whom the ID token belongs, if available.
   */
  picture?: string;

  /**
   * The `uid` corresponding to the user who the ID token belonged to.
   *
   * As a convenience, this value is copied over to the [`uid`](#uid) property.
   */
  sub: string;

  /**
   * The `uid` corresponding to the user who the ID token belonged to.
   *
   * This value is not actually in the JWT token claims itself. It is added as a
   * convenience, and is set as the value of the [`sub`](#sub) property.
   */
  uid: string;

  /**
   * Other arbitrary claims included in the ID token.
   */
  [key: string]: any;
}

export type VerifyJwtOptions = {
  /**
   * Seconds of clock skew to allow when checking `exp`, `iat` and `auth_time`.
   * @default 5
   */
  clockTolerance?: number;
};

export type VerifyIdTokenOptions = VerifyJwtOptions & {
  projectId: string;
  /**
   * Where to get Google's public keys. Defaults to `getGooglePublicKeys`, which
   * caches them. Tests can pass a function that returns their own keys.
   */
  fetchPublicKeys?: PublicKeysFetcher;
};

const DEFAULT_CLOCK_TOLERANCE_SECONDS = 5;
const MAX_UID_LENGTH = 128;
const MAX_IMPORTED_KEYS = 16;

// Google rotates a handful of keys, so caching the imported form saves an
// X.509 parse on every request.
const importedKeys = new Map<string, Promise<KeyLike>>();

const importVerificationKey = (key: string | KeyLike): Promise<KeyLike> => {
  if (typeof key !== "string") {
    return Promise.resolve(key);
  }
  let imported = importedKeys.get(key);
  if (!imported) {
    if (importedKeys.size >= MAX_IMPORTED_KEYS) {
      importedKeys.clear();
    }
    imported = importX509(key, "RS256");
    importedKeys.set(key, imported);
    imported.catch(() => importedKeys.delete(key));
  }
  return imported;
};

const readKid = (jwtToken: string): string => {
  let kid: string | undefined;
  try {
    kid = decodeProtectedHeader(jwtToken).kid;
  } catch {
    throw new JwtDecodeError("invalid jwt: cannot decode the protected header", "malformed");
  }
  if (!kid) {
    throw new JwtDecodeError("invalid jwt header does not contain kid", "malformed");
  }
  return kid;
};

const joseErrorCodes: Record<string, JwtDecodeErrorCode> = {
  ERR_JWT_EXPIRED: "expired",
  ERR_JWT_CLAIM_VALIDATION_FAILED: "invalid_claims",
  ERR_JWS_SIGNATURE_VERIFICATION_FAILED: "invalid_signature",
  ERR_JOSE_ALG_NOT_ALLOWED: "invalid_signature",
  ERR_JWS_INVALID: "malformed",
  ERR_JWT_INVALID: "malformed",
};

const toJwtDecodeError = (e: unknown): JwtDecodeError => {
  if (e instanceof JwtDecodeError) {
    return e;
  }
  const joseCode = (e as { code?: string } | undefined)?.code;
  const code = joseCode ? joseErrorCodes[joseCode] : undefined;
  if (code) {
    return new JwtDecodeError((e as Error).message, code);
  }
  // Not an expected rejection, so keep the details for debugging.
  console.error(e);
  return new JwtDecodeError("uncaught jwt decode exception", "malformed");
};

// Firebase rules that jwtVerify does not cover:
// https://firebase.google.com/docs/auth/admin/verify-id-tokens#verify_id_tokens_using_a_third-party_jwt_library
const assertFirebaseClaims = (payload: Record<string, unknown>, clockTolerance: number) => {
  const now = Math.floor(Date.now() / 1000) + clockTolerance;
  const { sub, iat, auth_time: authTime } = payload;
  if (typeof sub !== "string" || sub.length === 0 || sub.length > MAX_UID_LENGTH) {
    throw new JwtDecodeError(
      `"sub" claim must be a non-empty string of at most ${MAX_UID_LENGTH} characters`,
      "invalid_claims",
    );
  }
  if (typeof iat !== "number" || iat > now) {
    throw new JwtDecodeError('"iat" claim must be in the past', "invalid_claims");
  }
  if (typeof authTime !== "number" || authTime > now) {
    throw new JwtDecodeError('"auth_time" claim must be in the past', "invalid_claims");
  }
};

/**
 * Verifies a Firebase ID token against a known set of public keys.
 *
 * Throws `JwtDecodeError` with a `code` that says why the token was rejected.
 * Most callers should use `verifyIdToken`, which also fetches and caches keys.
 */
export const verifyAndDecodeJwt = async (
  jwtToken: string,
  publicKeys: VerificationKeys,
  projectId: string,
  options: VerifyJwtOptions = {},
): Promise<DecodedIdToken> => {
  const clockTolerance = options.clockTolerance ?? DEFAULT_CLOCK_TOLERANCE_SECONDS;
  try {
    const kid = readKid(jwtToken);
    const key = publicKeys[kid];
    if (!key) {
      throw new JwtDecodeError(
        "invalid kid or google public key has been updated recently",
        "unknown_key",
      );
    }
    const publicKey = await importVerificationKey(key);
    const { payload } = await jwtVerify(jwtToken, publicKey, {
      algorithms: ["RS256"],
      audience: projectId,
      issuer: `https://securetoken.google.com/${projectId}`,
      clockTolerance,
    });
    assertFirebaseClaims(payload, clockTolerance);

    return { ...payload, uid: payload.sub } as DecodedIdToken;
  } catch (e: unknown) {
    throw toJwtDecodeError(e);
  }
};

/**
 * Verifies a Firebase ID token, fetching Google's public keys as needed.
 *
 * Keys are cached. When the token's `kid` is not in the cache, the keys are
 * fetched again once, because Google rotates them.
 */
export const verifyIdToken = async (
  jwtToken: string,
  options: VerifyIdTokenOptions,
): Promise<DecodedIdToken> => {
  if (!options.projectId) {
    throw new Error("verifyIdToken: projectId is required");
  }
  const fetchPublicKeys = options.fetchPublicKeys ?? getGooglePublicKeys;
  const kid = readKid(jwtToken);
  let publicKeys = await fetchPublicKeys();
  if (!publicKeys[kid]) {
    publicKeys = await fetchPublicKeys({ forceRefresh: true });
  }
  return verifyAndDecodeJwt(jwtToken, publicKeys, options.projectId, options);
};
