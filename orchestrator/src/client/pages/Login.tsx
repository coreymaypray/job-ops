import { useState, useCallback, useEffect } from "react";
import { startAuthentication } from "@simplewebauthn/browser";
import { setAccessToken } from "@client/lib/auth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

interface LoginPageProps {
  onLogin: () => void;
}

export function LoginPage({ onLogin }: LoginPageProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [hasPasskeys, setHasPasskeys] = useState<boolean | null>(null);

  // Check on mount if admin has passkeys
  useEffect(() => {
    const controller = new AbortController();
    fetch("/api/auth/check", { signal: controller.signal })
      .then((r) => r.json())
      .then((data) => {
        const d = data.data ?? data;
        setHasPasskeys(d.hasPasskeys ?? false);
      })
      .catch(() => {
        if (!controller.signal.aborted) setHasPasskeys(false);
      });
    return () => controller.abort();
  }, []);

  const handlePasskeyLogin = useCallback(async () => {
    setError("");
    setLoading(true);
    try {
      // Get options
      const optRes = await fetch("/api/auth/webauthn/login/options", {
        method: "POST",
      });
      if (!optRes.ok) throw new Error("Failed to get passkey options");
      const optData = await optRes.json();
      const options = optData.data ?? optData;

      // Trigger browser/1Password prompt
      const assertion = await startAuthentication({ optionsJSON: options });

      // Verify
      const verifyRes = await fetch("/api/auth/webauthn/login/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(assertion),
        credentials: "include",
      });

      if (!verifyRes.ok) {
        let message = "Passkey verification failed";
        try {
          const errData = await verifyRes.json();
          message = errData.error?.message || message;
        } catch { /* non-JSON response */ }
        throw new Error(message);
      }

      const verifyData = await verifyRes.json();
      const token = verifyData.data?.accessToken ?? verifyData.accessToken ?? null;
      setAccessToken(token);
      onLogin();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Passkey login failed");
    } finally {
      setLoading(false);
    }
  }, [onLogin]);

  const handlePasswordLogin = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setError("");
      setLoading(true);
      try {
        const res = await fetch("/api/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password, totpCode }),
          credentials: "include",
        });

        if (res.status === 423) {
          setError("Account locked. Run: npm run unlock:admin");
          return;
        }

        if (!res.ok) {
          let message = "Invalid credentials";
          try {
            const errData = await res.json();
            message = errData.error?.message || message;
          } catch { /* non-JSON response */ }
          setError(message);
          return;
        }

        const data = await res.json();
        const token = data.data?.accessToken ?? data.accessToken ?? null;
        setAccessToken(token);
        onLogin();
      } catch {
        setError("Login failed. Check your connection.");
      } finally {
        setLoading(false);
      }
    },
    [username, password, totpCode, onLogin],
  );

  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <div className="w-full max-w-sm space-y-6 rounded-lg border p-6">
        <div className="text-center">
          <h1 className="text-2xl font-bold">Sloth Jobs</h1>
        </div>

        {hasPasskeys && (
          <>
            <Button
              type="button"
              onClick={handlePasskeyLogin}
              disabled={loading}
              className="w-full"
              size="lg"
            >
              Sign in with Passkey
            </Button>
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <span className="w-full border-t" />
              </div>
              <div className="relative flex justify-center text-xs uppercase">
                <span className="bg-background px-2 text-muted-foreground">
                  or sign in manually
                </span>
              </div>
            </div>
          </>
        )}

        <form onSubmit={handlePasswordLogin} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="username">Username</Label>
            <Input
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              disabled={loading}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="password">Password</Label>
            <Input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              disabled={loading}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="totp">Authentication Code</Label>
            <Input
              id="totp"
              value={totpCode}
              onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              placeholder="000000"
              maxLength={6}
              autoComplete="one-time-code"
              disabled={loading}
            />
          </div>

          {error && (
            <p className="text-sm text-destructive" role="alert">{error}</p>
          )}

          <Button type="submit" disabled={loading} className="w-full">
            {loading ? "Signing in..." : "Sign In"}
          </Button>
        </form>

        <p className="text-center text-xs text-muted-foreground">
          Account locked? Run: <code>npm run unlock:admin</code>
        </p>
      </div>
    </div>
  );
}
