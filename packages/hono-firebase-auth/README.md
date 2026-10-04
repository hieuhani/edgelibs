# Firebase Authentication/Identity Platform integration for Hono

This package allows easily integrate Firebase Authentication/Identity Platform to your Hono API project. It runs anywhere Hono runs, including Cloudflare Workers, and needs no service-account key.

## Features

- Hono middleware to decode and verify JWT token issued by Firebase Authentication service
- Google's public keys are cached for as long as Google's `Cache-Control: max-age` allows, and refetched once when a token uses a new key
- Errors carry a `code` (`expired`, `invalid_signature`, `invalid_claims`, `unknown_key`, `malformed`) so clients know when to refresh a token
- Hono context variable `currentUser`, typed together with your bindings when you pass your Env type
- Allowed to custom `currentUser` shape, with sync or async transforms
- Choose where the token comes from, and skip requests that use other kinds of tokens

Requires Hono 4.

## Install

With NPM

```bash
npm install @fiboup/hono-firebase-auth
```

With pnpm

```bash
pnpm add @fiboup/hono-firebase-auth
```

With Bun

```bash
bun add @fiboup/hono-firebase-auth
```

## Usage

### Add authentication middleware to your Hono app

```ts
import { Hono } from "hono";
import { validateFirebaseAuth } from "@fiboup/hono-firebase-auth";
import type { DefaultFirebaseAuthInjectedVariables } from "@fiboup/hono-firebase-auth";

const app = new Hono<{ Variables: DefaultFirebaseAuthInjectedVariables }>();
app.use(
  "*",
  validateFirebaseAuth({
    projectId: "<your_firebase_project_id>",
  })
);

app.get("/me", (c) => {
  const currentUser = c.get("currentUser"); // DecodedIdToken | undefined
  return c.json(currentUser);
});
```

***Note: Go to your Firebase project, then visit Project settings for the project id***

Requests without a token pass through with no `currentUser`. Add your own check on routes that require a signed-in user.

### Read the project ID from the environment

On Cloudflare Workers, `c.env` is only available inside a request, so `projectId` can be a function:

```ts
type Env = { Bindings: { FIREBASE_PROJECT_ID: string } };

app.use(
  "*",
  validateFirebaseAuth<DecodedIdToken, "currentUser", Env>({
    projectId: (c) => c.env.FIREBASE_PROJECT_ID,
  })
);
```

### Handle token errors

An invalid token throws `JwtDecodeError`. Its `code` says why:

```ts
import { JwtDecodeError, PublicKeysFetchError } from "@fiboup/hono-firebase-auth";

app.onError((err, c) => {
  if (err instanceof JwtDecodeError) {
    // "expired" means the client should refresh its ID token and retry.
    return c.json({ error: { message: err.message, code: err.code } }, 401);
  }
  if (err instanceof PublicKeysFetchError) {
    // Google's keys could not be fetched. This is not the client's fault.
    return c.json({ error: { message: "Authentication is unavailable" } }, 503);
  }
  return c.json({ error: { message: "Uncaught exception" } }, 500);
});
```

### Choose where the token comes from

By default the token is read from `Authorization: Bearer <token>`. Pass `getToken` to read it from somewhere else. Returning `undefined` passes the request through unchanged, which lets Firebase sit next to another kind of token:

```ts
app.use(
  "*",
  validateFirebaseAuth({
    projectId: "<your_firebase_project_id>",
    getToken: (c) => {
      const token = c.req.header("Authorization")?.replace(/^Bearer /, "");
      // API keys start with "ft_" and are checked by a later middleware.
      return token?.startsWith("ft_") ? undefined : token;
    },
  })
);
```

### Custom current user context info with `transformCurrentUser`

The transform may be async, and its return type becomes the type of the context variable:

```ts
type Member = { firebaseUid: string; email?: string };

const app = new Hono<{ Variables: { member?: Member } }>();
app.use(
  "*",
  validateFirebaseAuth({
    projectId: "<your_firebase_project_id>",
    currentUserContextKey: "member",
    transformCurrentUser: async (decodedToken): Promise<Member> => ({
      firebaseUid: decodedToken.uid,
      email: decodedToken.email,
    }),
  })
);
```

Leave `currentUserContextKey` as an empty string to disable setting the context variable.

### Verify a token outside the middleware

For example, during a WebSocket upgrade:

```ts
import { verifyIdToken } from "@fiboup/hono-firebase-auth";

const decodedToken = await verifyIdToken(token, { projectId: "<your_firebase_project_id>" });
```

### Testing

Pass `fetchPublicKeys` to use your own keys instead of Google's. Keys can be PEM certificates or keys imported with `jose`:

```ts
import { SignJWT, generateKeyPair } from "jose";

const { privateKey, publicKey } = await generateKeyPair("RS256");
app.use(
  "*",
  validateFirebaseAuth({
    projectId: "test-project",
    fetchPublicKeys: async () => ({ "test-kid": publicKey }),
  })
);
```

## What is checked

The signature uses RS256 and Google's `securetoken` keys. `aud` must equal the project ID, `iss` must equal `https://securetoken.google.com/<projectId>`, and `exp` must be in the future. `iat` and `auth_time` must be in the past, and `sub` must be a non-empty string of at most 128 characters. Each time check allows 5 seconds of clock skew, which you can change with `clockTolerance`. The decoded token's `uid` is set to `sub`.

Revocation is not checked, because that needs the Firebase Admin API. If you need to cut off access before a token expires, check your own user records on each request.

## Migrating from 1.x

- Hono 4 is required. The peer range was `^3.12.12`.
- `transformCurrentUser` is no longer a generic function. Its return type sets the type of the context variable, and it also receives the Hono context.
- `JwtDecodeError` now has a `code`. Expired tokens no longer write to `console.error`.
- `currentUser.uid` is now set. In 1.x it was always `undefined`.
- Tokens with an empty or overlong `sub`, or an `iat` or `auth_time` in the future, are now rejected.
- Code that only used `projectId` and read `currentUser.sub` works unchanged.

## License

MIT &copy; [Fiboup](https://github.com/fiboup)
