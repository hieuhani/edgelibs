import { JwtDecodeError, validateFirebaseAuth } from "../src";
import type { DecodedIdToken, DefaultFirebaseAuthInjectedVariables } from "../src";
import { Hono } from "hono";
import { SignJWT, generateKeyPair } from "jose";
import type { KeyLike } from "jose";
import { beforeAll, describe, expect, it } from "vitest";

const projectId = "test-project";
const kid = "key-1";
const now = () => Math.floor(Date.now() / 1000);

let privateKey: KeyLike;
let publicKey: KeyLike;
const fetchPublicKeys = async () => ({ [kid]: publicKey });

beforeAll(async () => {
  ({ privateKey, publicKey } = await generateKeyPair("RS256"));
});

const signToken = (exp = now() + 3600) =>
  new SignJWT({ auth_time: now() - 60, email: "dev@fibotree.app", email_verified: true })
    .setProtectedHeader({ alg: "RS256", kid })
    .setIssuer(`https://securetoken.google.com/${projectId}`)
    .setAudience(projectId)
    .setSubject("user-123")
    .setIssuedAt(now() - 10)
    .setExpirationTime(exp)
    .sign(privateKey);

const withErrorHandler = <T extends Hono<any>>(app: T) => {
  app.onError((err, c) => {
    if (err instanceof JwtDecodeError) {
      return c.json({ code: err.code }, 401);
    }
    return c.json({ message: err.message }, 500);
  });
  return app;
};

const bearer = (token: string) => ({ headers: { Authorization: `Bearer ${token}` } });

describe("validateFirebaseAuth", () => {
  it("passes requests without a token through with no user", async () => {
    const app = new Hono<{ Variables: DefaultFirebaseAuthInjectedVariables }>();
    app.use("*", validateFirebaseAuth({ projectId, fetchPublicKeys }));
    app.get("/", (c) => c.json({ user: c.get("currentUser") ?? null }));

    const res = await app.request("/");
    expect(await res.json()).toEqual({ user: null });
  });

  it("sets currentUser with uid for a valid token", async () => {
    const app = new Hono<{ Variables: DefaultFirebaseAuthInjectedVariables }>();
    app.use("*", validateFirebaseAuth({ projectId, fetchPublicKeys }));
    app.get("/", (c) => c.json(c.get("currentUser")));

    const res = await app.request("/", bearer(await signToken()));
    const user = (await res.json()) as DecodedIdToken;
    expect(res.status).toBe(200);
    expect(user.uid).toBe("user-123");
    expect(user.email_verified).toBe(true);
  });

  it("reads projectId from the context", async () => {
    type Env = { Bindings: { FIREBASE_PROJECT_ID: string } };
    const app = new Hono<Env>();
    app.use(
      "*",
      validateFirebaseAuth<DecodedIdToken, "currentUser", Env>({
        projectId: (c) => c.env.FIREBASE_PROJECT_ID,
        fetchPublicKeys,
      }),
    );
    app.get("/", (c) => c.text("ok"));

    const res = await app.request("/", bearer(await signToken()), {
      FIREBASE_PROJECT_ID: projectId,
    });
    expect(res.status).toBe(200);
  });

  it("lets getToken skip non-Firebase tokens", async () => {
    const app = withErrorHandler(new Hono<{ Variables: DefaultFirebaseAuthInjectedVariables }>());
    app.use(
      "*",
      validateFirebaseAuth({
        projectId,
        fetchPublicKeys,
        getToken: (c) => {
          const token = c.req.header("Authorization")?.replace(/^Bearer /, "");
          return token?.startsWith("ft_") ? undefined : token;
        },
      }),
    );
    app.get("/", (c) => c.json({ user: c.get("currentUser") ?? null }));

    const res = await app.request("/", bearer("ft_agent_token"));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ user: null });
  });

  it("supports an async, typed transformCurrentUser and a custom key", async () => {
    type Member = { firebaseUid: string; email?: string };
    const app = new Hono<{ Variables: { member?: Member } }>();
    app.use(
      "*",
      validateFirebaseAuth({
        projectId,
        fetchPublicKeys,
        currentUserContextKey: "member",
        transformCurrentUser: async (token): Promise<Member> => ({
          firebaseUid: token.uid,
          email: token.email,
        }),
      }),
    );
    app.get("/", (c) => c.json(c.get("member")));

    const res = await app.request("/", bearer(await signToken()));
    expect(await res.json()).toEqual({ firebaseUid: "user-123", email: "dev@fibotree.app" });
  });

  it("does not set a user when the context key is empty", async () => {
    const app = new Hono<{ Variables: DefaultFirebaseAuthInjectedVariables }>();
    app.use("*", validateFirebaseAuth({ projectId, fetchPublicKeys, currentUserContextKey: "" }));
    app.get("/", (c) => c.json({ user: c.get("currentUser") ?? null }));

    const res = await app.request("/", bearer(await signToken()));
    expect(await res.json()).toEqual({ user: null });
  });

  it("throws JwtDecodeError with code expired for an expired token", async () => {
    const app = withErrorHandler(new Hono());
    app.use("*", validateFirebaseAuth({ projectId, fetchPublicKeys }));
    app.get("/", (c) => c.text("ok"));

    const res = await app.request("/", bearer(await signToken(now() - 60)));
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ code: "expired" });
  });
});
