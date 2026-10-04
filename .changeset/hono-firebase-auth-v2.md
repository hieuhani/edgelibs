---
"@fiboup/hono-firebase-auth": major
---

Version 2 for Hono 4.

- Requires Hono 4 (`peerDependencies: hono ^4.0.0`).
- New `getToken` option. Return `undefined` to pass a request through, so Firebase can sit next to other kinds of tokens.
- `projectId` can be a function of the Hono context, such as `(c) => c.env.FIREBASE_PROJECT_ID`.
- `transformCurrentUser` is typed by its return value, may be async, and receives the context. Pass your Env as the third type parameter to type bindings and the user variable together. Without it, the handler accepts any context, as in 1.x, so existing wrappers such as `(c, next) => validateFirebaseAuth({...})(c, next)` keep compiling.
- Google's public keys are cached and refetched once on an unknown `kid`. Tests can inject keys with `fetchPublicKeys`.
- Re-exports `verifyIdToken`, `PublicKeysFetchError` and `JwtDecodeErrorCode`.
