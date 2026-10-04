/**
 * Why a Firebase ID token was rejected.
 *
 * - `expired`: the token is past `exp`. The client should refresh it and retry.
 * - `invalid_signature`: the signature does not match Google's key for `kid`.
 * - `invalid_claims`: `aud`, `iss`, `sub`, `iat` or `auth_time` is wrong.
 * - `unknown_key`: `kid` is not one of Google's current keys, even after a refresh.
 * - `malformed`: the value is not a well-formed JWT.
 */
export type JwtDecodeErrorCode =
  | "expired"
  | "invalid_signature"
  | "invalid_claims"
  | "unknown_key"
  | "malformed";

export class JwtDecodeError extends Error {
  readonly code: JwtDecodeErrorCode;

  constructor(error: string, code: JwtDecodeErrorCode = "malformed") {
    super(error);
    this.name = "JwtDecodeError";
    this.code = code;
  }
}

/**
 * Google's public keys could not be fetched. This is a server-side failure,
 * not a problem with the client's token.
 */
export class PublicKeysFetchError extends Error {
  readonly status?: number;

  constructor(message: string, status?: number) {
    super(message);
    this.name = "PublicKeysFetchError";
    this.status = status;
  }
}

export type IdentityErrorResponse = {
  error: {
    code: number;
    message: string;
    errors: {
      message: string;
      reason: "invalid";
      domain: string;
    }[];
  };
};

export class IdentityError extends Error {
  readonly errorResponse: IdentityErrorResponse;
  constructor(errorResponse: IdentityErrorResponse) {
    super();
    this.errorResponse = errorResponse;
  }

  getResponse(): Response {
    return new Response(
      JSON.stringify({
        success: false,
        error: {
          message: this.errorResponse.error.message,
        },
      }),
      {
        status: this.errorResponse.error.code,
        headers: {
          "Content-Type": "application/json",
        },
      },
    );
  }
}
