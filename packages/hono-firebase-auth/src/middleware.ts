import { verifyIdToken } from "@fiboup/firebase-auth";
import type { DecodedIdToken, PublicKeysFetcher } from "@fiboup/firebase-auth";
import type { Context, Env, MiddlewareHandler } from "hono";
import { createMiddleware } from "hono/factory";

const tokenPrefix = "Bearer ";
const defaultCurrentUserContextKey = "currentUser";

export type FirebaseAuthConfig<
  TUser = DecodedIdToken,
  TKey extends string = typeof defaultCurrentUserContextKey,
  E extends Env = any,
> = {
  /**
   * Your Firebase project ID, or a function that reads it from the context,
   * for example `(c) => c.env.FIREBASE_PROJECT_ID` on Cloudflare Workers.
   */
  projectId: string | ((c: Context<E>) => string);
  /**
   * Returns the Firebase ID token for this request. Return `undefined` when the
   * request is not using Firebase, and the middleware passes it on unchanged.
   * Defaults to the token in an `Authorization: Bearer <token>` header.
   */
  getToken?: (c: Context<E>) => string | null | undefined;
  /** Shapes the value stored in the context. May be async. */
  transformCurrentUser?: (decodedToken: DecodedIdToken, c: Context<E>) => TUser | Promise<TUser>;
  /**
   * Context variable that holds the current user. Set to an empty string ("")
   * to skip setting it.
   * @default "currentUser"
   */
  currentUserContextKey?: TKey;
  /** Where to get Google's public keys. Defaults to a cached fetch. */
  fetchPublicKeys?: PublicKeysFetcher;
  /**
   * Seconds of clock skew to allow when checking token times.
   * @default 5
   */
  clockTolerance?: number;
};

export type FirebaseAuthVariables<
  TUser = DecodedIdToken,
  TKey extends string = typeof defaultCurrentUserContextKey,
> = { [K in TKey]?: TUser };

export type DefaultFirebaseAuthInjectedVariables = FirebaseAuthVariables;

export const defaultTransformCurrentUser = (decodedToken: DecodedIdToken) => {
  return decodedToken;
};

export const getBearerToken = (c: Context): string | undefined => {
  const header = c.req.header("Authorization");
  if (!header?.startsWith(tokenPrefix)) {
    return undefined;
  }
  return header.substring(tokenPrefix.length) || undefined;
};

/**
 * Verifies the Firebase ID token on a request and stores the current user in
 * the context. Requests without a token pass through with no user set, so
 * add your own check on routes that require one.
 *
 * An invalid token throws `JwtDecodeError`. Handle it in `app.onError`.
 */
export const validateFirebaseAuth = <
  TUser = DecodedIdToken,
  TKey extends string = typeof defaultCurrentUserContextKey,
  E extends Env = any,
>(
  config: FirebaseAuthConfig<TUser, TKey, E>,
): MiddlewareHandler<E & { Variables: FirebaseAuthVariables<TUser, TKey> }> => {
  // With the default `E = any` the handler accepts any context, as in 1.x.
  // Pass your Env as `E` to get bindings and the user variable typed together.
  return createMiddleware<E & { Variables: FirebaseAuthVariables<TUser, TKey> }>(
    async (c, next) => {
      const context = c as unknown as Context<E>;
      const token = config.getToken ? config.getToken(context) : getBearerToken(c as Context);
      if (!token) {
        return await next();
      }

      const projectId =
        typeof config.projectId === "function" ? config.projectId(context) : config.projectId;
      const decodedToken = await verifyIdToken(token, {
        projectId,
        fetchPublicKeys: config.fetchPublicKeys,
        clockTolerance: config.clockTolerance,
      });

      const transformCurrentUser =
        config.transformCurrentUser ??
        (defaultTransformCurrentUser as unknown as (decodedToken: DecodedIdToken) => TUser);
      const currentUser = await transformCurrentUser(decodedToken, context);

      const key = config.currentUserContextKey ?? defaultCurrentUserContextKey;
      if (key !== "") {
        c.set(key as never, currentUser as never);
      }

      await next();
    },
  );
};

export type { DecodedIdToken };
