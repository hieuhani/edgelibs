import { PublicKeysFetchError, clearGooglePublicKeysCache, getGooglePublicKeys } from "../src";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const keysResponse = (keys: Record<string, string>, cacheControl?: string, status = 200) =>
  new Response(JSON.stringify(keys), {
    status,
    headers: cacheControl ? { "Cache-Control": cacheControl } : {},
  });

describe("getGooglePublicKeys", () => {
  const fetchMock = vi.fn<Parameters<typeof fetch>, ReturnType<typeof fetch>>();

  beforeEach(() => {
    clearGooglePublicKeysCache();
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("caches keys until max-age expires", async () => {
    fetchMock
      .mockResolvedValueOnce(keysResponse({ a: "pem-a" }, "public, max-age=100"))
      .mockResolvedValueOnce(keysResponse({ b: "pem-b" }, "public, max-age=100"));

    expect(await getGooglePublicKeys()).toEqual({ a: "pem-a" });
    vi.advanceTimersByTime(99_000);
    expect(await getGooglePublicKeys()).toEqual({ a: "pem-a" });
    expect(fetchMock).toHaveBeenCalledTimes(1);

    vi.advanceTimersByTime(2_000);
    expect(await getGooglePublicKeys()).toEqual({ b: "pem-b" });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("refetches when forceRefresh is set", async () => {
    fetchMock
      .mockResolvedValueOnce(keysResponse({ a: "pem-a" }, "max-age=3600"))
      .mockResolvedValueOnce(keysResponse({ b: "pem-b" }, "max-age=3600"));

    await getGooglePublicKeys();
    expect(await getGooglePublicKeys({ forceRefresh: true })).toEqual({ b: "pem-b" });
  });

  it("shares one request between concurrent callers", async () => {
    fetchMock.mockResolvedValue(keysResponse({ a: "pem-a" }, "max-age=3600"));
    await Promise.all([getGooglePublicKeys(), getGooglePublicKeys(), getGooglePublicKeys()]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("throws PublicKeysFetchError on a non-2xx response and does not cache it", async () => {
    fetchMock
      .mockResolvedValueOnce(keysResponse({}, undefined, 503))
      .mockResolvedValueOnce(keysResponse({ a: "pem-a" }, "max-age=3600"));

    const error = await getGooglePublicKeys().catch((e) => e);
    expect(error).toBeInstanceOf(PublicKeysFetchError);
    expect(error.status).toBe(503);
    expect(await getGooglePublicKeys()).toEqual({ a: "pem-a" });
  });
});
