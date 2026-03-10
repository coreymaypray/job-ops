import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  authFetch,
  getAccessToken,
  isAuthenticated,
  logout,
  refreshAccessToken,
  setAccessToken,
} from "./auth";

describe("client auth utilities", () => {
  beforeEach(() => {
    setAccessToken(null);
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        Promise.resolve(new Response("default", { status: 500 })),
      ),
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  function mockFetch() {
    return globalThis.fetch as ReturnType<typeof vi.fn>;
  }

  // --- getAccessToken / setAccessToken ---

  it("getAccessToken returns null initially", () => {
    expect(getAccessToken()).toBeNull();
  });

  it("setAccessToken stores and getAccessToken retrieves the token", () => {
    setAccessToken("test-token-123");
    expect(getAccessToken()).toBe("test-token-123");
  });

  it("setAccessToken(null) clears the token", () => {
    setAccessToken("some-token");
    setAccessToken(null);
    expect(getAccessToken()).toBeNull();
  });

  // --- isAuthenticated ---

  it("isAuthenticated returns false when no token is set", () => {
    expect(isAuthenticated()).toBe(false);
  });

  it("isAuthenticated returns true when a token is set", () => {
    setAccessToken("valid-token");
    expect(isAuthenticated()).toBe(true);
  });

  // --- refreshAccessToken ---

  it("refreshAccessToken returns new token on success", async () => {
    mockFetch().mockResolvedValueOnce(
      new Response(JSON.stringify({ data: { accessToken: "new-token" } }), {
        status: 200,
      }),
    );

    const token = await refreshAccessToken();
    expect(token).toBe("new-token");
    expect(getAccessToken()).toBe("new-token");
    expect(mockFetch()).toHaveBeenCalledWith("/api/auth/refresh", {
      method: "POST",
      credentials: "include",
    });
  });

  it("refreshAccessToken handles flat response shape", async () => {
    mockFetch().mockResolvedValueOnce(
      new Response(JSON.stringify({ accessToken: "flat-token" }), {
        status: 200,
      }),
    );

    const token = await refreshAccessToken();
    expect(token).toBe("flat-token");
    expect(getAccessToken()).toBe("flat-token");
  });

  it("refreshAccessToken returns null on HTTP failure", async () => {
    setAccessToken("old-token");
    mockFetch().mockResolvedValueOnce(
      new Response("Unauthorized", { status: 401 }),
    );

    const token = await refreshAccessToken();
    expect(token).toBeNull();
    expect(getAccessToken()).toBeNull();
  });

  it("refreshAccessToken returns null on network error", async () => {
    setAccessToken("old-token");
    mockFetch().mockRejectedValueOnce(new Error("Network error"));

    const token = await refreshAccessToken();
    expect(token).toBeNull();
    expect(getAccessToken()).toBeNull();
  });

  it("refreshAccessToken deduplicates concurrent calls", async () => {
    let resolveRefresh!: (value: Response) => void;
    mockFetch().mockImplementationOnce(
      () =>
        new Promise<Response>((resolve) => {
          resolveRefresh = resolve;
        }),
    );

    // Fire two concurrent refreshes
    const p1 = refreshAccessToken();
    const p2 = refreshAccessToken();

    // Resolve the single fetch call
    resolveRefresh(
      new Response(
        JSON.stringify({ data: { accessToken: "deduped-token" } }),
        { status: 200 },
      ),
    );

    const [t1, t2] = await Promise.all([p1, p2]);
    expect(t1).toBe("deduped-token");
    expect(t2).toBe("deduped-token");

    // fetch was only called once — deduplication worked
    expect(mockFetch()).toHaveBeenCalledTimes(1);
  });

  // --- authFetch ---

  it("authFetch adds Authorization header when token exists", async () => {
    setAccessToken("my-jwt");
    mockFetch().mockResolvedValueOnce(new Response("OK", { status: 200 }));

    await authFetch("/api/data");

    const callArgs = mockFetch().mock.calls[0];
    const headers = callArgs[1]?.headers as Headers;
    expect(headers.get("Authorization")).toBe("Bearer my-jwt");
    expect(callArgs[1]?.credentials).toBe("include");
  });

  it("authFetch does not add Authorization header when no token", async () => {
    mockFetch().mockResolvedValueOnce(new Response("OK", { status: 200 }));

    await authFetch("/api/data");

    const callArgs = mockFetch().mock.calls[0];
    const headers = callArgs[1]?.headers as Headers;
    expect(headers.get("Authorization")).toBeNull();
  });

  it("authFetch retries on 401 after successful refresh", async () => {
    setAccessToken("expired-token");

    const fn = mockFetch();
    // First call (authFetch initial): 401
    fn.mockResolvedValueOnce(
      new Response("Unauthorized", { status: 401 }),
    );
    // Second call (refreshAccessToken): success with new token
    fn.mockResolvedValueOnce(
      new Response(
        JSON.stringify({ data: { accessToken: "refreshed-token" } }),
        { status: 200 },
      ),
    );
    // Third call (authFetch retry): success
    fn.mockResolvedValueOnce(new Response("Success", { status: 200 }));

    const res = await authFetch("/api/protected");

    expect(res.status).toBe(200);
    expect(fn).toHaveBeenCalledTimes(3);

    // Verify the retry used the refreshed token
    const retryHeaders = fn.mock.calls[2][1]?.headers as Headers;
    expect(retryHeaders.get("Authorization")).toBe("Bearer refreshed-token");
  });

  it("authFetch does not retry when refresh fails", async () => {
    setAccessToken("expired-token");

    const fn = mockFetch();
    // First call (authFetch initial): 401
    fn.mockResolvedValueOnce(
      new Response("Unauthorized", { status: 401 }),
    );
    // Second call (refreshAccessToken): failure
    fn.mockResolvedValueOnce(
      new Response("Forbidden", { status: 403 }),
    );

    const res = await authFetch("/api/protected");

    // Returns the original 401 response
    expect(res.status).toBe(401);
    // Only 2 calls: original + refresh attempt (no retry)
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it("authFetch does not attempt refresh when no token was set", async () => {
    mockFetch().mockResolvedValueOnce(
      new Response("Unauthorized", { status: 401 }),
    );

    const res = await authFetch("/api/protected");

    expect(res.status).toBe(401);
    // Only 1 call — no refresh attempted
    expect(mockFetch()).toHaveBeenCalledTimes(1);
  });

  // --- logout ---

  it("logout clears token and calls server", async () => {
    setAccessToken("active-token");
    mockFetch().mockResolvedValueOnce(new Response("OK", { status: 200 }));

    await logout();

    expect(getAccessToken()).toBeNull();
    expect(isAuthenticated()).toBe(false);
    expect(mockFetch()).toHaveBeenCalledWith("/api/auth/logout", {
      method: "POST",
      credentials: "include",
    });
  });

  it("logout clears token even when server call fails", async () => {
    setAccessToken("active-token");
    mockFetch().mockRejectedValueOnce(new Error("Network error"));

    await logout();

    expect(getAccessToken()).toBeNull();
    expect(isAuthenticated()).toBe(false);
  });
});
