import { JwtDecodeError, verifyAndDecodeJwt, verifyIdToken } from "../src";
import type { PublicKeysFetcher, VerificationKeys } from "../src";
import { SignJWT, generateKeyPair } from "jose";
import type { KeyLike } from "jose";
import { beforeAll, describe, expect, it, vi } from "vitest";

const projectId = "test-project";
const kid = "key-1";
const now = () => Math.floor(Date.now() / 1000);

let privateKey: KeyLike;
let publicKey: KeyLike;
let otherPrivateKey: KeyLike;

beforeAll(async () => {
  ({ privateKey, publicKey } = await generateKeyPair("RS256"));
  ({ privateKey: otherPrivateKey } = await generateKeyPair("RS256"));
});

type TokenOverrides = {
  claims?: Record<string, unknown>;
  kid?: string;
  key?: KeyLike;
  exp?: number;
};

const signToken = ({ claims = {}, kid: tokenKid = kid, key, exp }: TokenOverrides = {}) =>
  new SignJWT({ sub: "user-123", auth_time: now() - 60, email: "dev@fibotree.app", ...claims })
    .setProtectedHeader({ alg: "RS256", kid: tokenKid })
    .setIssuer(`https://securetoken.google.com/${projectId}`)
    .setAudience(projectId)
    .setIssuedAt(now() - 10)
    .setExpirationTime(exp ?? now() + 3600)
    .sign(key ?? privateKey);

const expectCode = async (promise: Promise<unknown>, code: JwtDecodeError["code"]) => {
  const error = (await promise.catch((e) => e)) as JwtDecodeError;
  expect(error).toBeInstanceOf(JwtDecodeError);
  expect(error.code).toBe(code);
};

describe("verifyAndDecodeJwt", () => {
  it("returns the payload with uid copied from sub", async () => {
    const decoded = await verifyAndDecodeJwt(await signToken(), { [kid]: publicKey }, projectId);
    expect(decoded.sub).toBe("user-123");
    expect(decoded.uid).toBe("user-123");
    expect(decoded.email).toBe("dev@fibotree.app");
  });

  it("rejects an expired token with code expired", async () => {
    const token = await signToken({ exp: now() - 60 });
    await expectCode(verifyAndDecodeJwt(token, { [kid]: publicKey }, projectId), "expired");
  });

  it("rejects a token signed by another key with code invalid_signature", async () => {
    const token = await signToken({ key: otherPrivateKey });
    await expectCode(
      verifyAndDecodeJwt(token, { [kid]: publicKey }, projectId),
      "invalid_signature",
    );
  });

  it("rejects a token for another project with code invalid_claims", async () => {
    await expectCode(
      verifyAndDecodeJwt(await signToken(), { [kid]: publicKey }, "other-project"),
      "invalid_claims",
    );
  });

  it.each([
    ["an empty sub", { sub: "" }],
    ["a sub longer than 128 characters", { sub: "a".repeat(129) }],
    ["auth_time in the future", { auth_time: now() + 3600 }],
    ["a missing auth_time", { auth_time: undefined }],
  ])("rejects %s with code invalid_claims", async (_name, claims) => {
    const token = await signToken({ claims });
    await expectCode(verifyAndDecodeJwt(token, { [kid]: publicKey }, projectId), "invalid_claims");
  });

  it("rejects an unknown kid with code unknown_key", async () => {
    const token = await signToken({ kid: "rotated-away" });
    await expectCode(verifyAndDecodeJwt(token, { [kid]: publicKey }, projectId), "unknown_key");
  });

  it("rejects a value that is not a JWT with code malformed", async () => {
    await expectCode(
      verifyAndDecodeJwt("ft_agent_token", { [kid]: publicKey }, projectId),
      "malformed",
    );
  });
});

describe("verifyIdToken", () => {
  it("fetches keys again once when the kid is not in the cached set", async () => {
    const fetchPublicKeys = vi.fn<Parameters<PublicKeysFetcher>, ReturnType<PublicKeysFetcher>>(
      async (options): Promise<VerificationKeys> =>
        options?.forceRefresh ? { [kid]: publicKey } : {},
    );
    const decoded = await verifyIdToken(await signToken(), { projectId, fetchPublicKeys });
    expect(decoded.uid).toBe("user-123");
    expect(fetchPublicKeys).toHaveBeenCalledTimes(2);
    expect(fetchPublicKeys).toHaveBeenLastCalledWith({ forceRefresh: true });
  });

  it("does not refetch when the kid is already known", async () => {
    const fetchPublicKeys = vi.fn(async () => ({ [kid]: publicKey }));
    await verifyIdToken(await signToken(), { projectId, fetchPublicKeys });
    expect(fetchPublicKeys).toHaveBeenCalledTimes(1);
  });

  it("requires a projectId", async () => {
    await expect(verifyIdToken(await signToken(), { projectId: "" })).rejects.toThrow(
      "projectId is required",
    );
  });
});
