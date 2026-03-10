import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

interface SetupPageProps {
  onSetupComplete: () => void;
}

type Step = "credentials" | "qr" | "verify";

export function SetupPage({ onSetupComplete }: SetupPageProps) {
  const [step, setStep] = useState<Step>("credentials");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  // QR step state
  const [qrCodeDataUri, setQrCodeDataUri] = useState("");
  const [manualKey, setManualKey] = useState("");
  const [setupToken, setSetupToken] = useState("");

  // Verify step state
  const [totpCode, setTotpCode] = useState("");

  const handleCredentialsSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (password !== confirmPassword) {
      setError("Passwords don't match");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch("/api/auth/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.trim(), password }),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => null);
        setError(data?.error?.message || "Setup failed");
        return;
      }

      const data = await res.json();
      const d = data.data ?? data;
      setQrCodeDataUri(d.qrCodeDataUri);
      setManualKey(d.manualKey);
      setSetupToken(d.setupToken);
      setStep("qr");
    } catch {
      setError("Connection failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const res = await fetch("/api/auth/setup/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ setupToken, totpCode }),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => null);
        setError(data?.error?.message || "Verification failed");
        return;
      }

      onSetupComplete();
    } catch {
      setError("Connection failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <div className="w-full max-w-sm space-y-6 rounded-lg border p-6">
        <div className="text-center">
          <h1 className="text-2xl font-bold">Sloth Jobs</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            {step === "credentials" && "Create your admin account"}
            {step === "qr" && "Set up two-factor authentication"}
            {step === "verify" && "Verify your authenticator"}
          </p>
        </div>

        {step === "credentials" && (
          <form onSubmit={handleCredentialsSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="setup-username">Username</Label>
              <Input
                id="setup-username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                disabled={loading}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="setup-password">Password</Label>
              <Input
                id="setup-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="new-password"
                disabled={loading}
                required
              />
              <p className="text-xs text-muted-foreground">
                Min 12 chars, uppercase, lowercase, number, special character
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="setup-confirm">Confirm Password</Label>
              <Input
                id="setup-confirm"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                autoComplete="new-password"
                disabled={loading}
                required
              />
            </div>

            {error && (
              <p className="text-sm text-destructive" role="alert">{error}</p>
            )}

            <Button type="submit" disabled={loading} className="w-full">
              {loading ? "Setting up..." : "Continue"}
            </Button>
          </form>
        )}

        {step === "qr" && (
          <div className="space-y-4">
            <div className="flex justify-center">
              <img
                src={qrCodeDataUri}
                alt="TOTP QR Code"
                className="h-48 w-48 rounded-lg border"
              />
            </div>
            <div className="space-y-1">
              <p className="text-xs text-muted-foreground">
                Scan this QR code with your authenticator app (Google Authenticator, 1Password, etc.)
              </p>
              <p className="text-xs text-muted-foreground">
                Manual key: <code className="rounded bg-muted px-1 py-0.5 text-xs">{manualKey}</code>
              </p>
            </div>
            <Button onClick={() => setStep("verify")} className="w-full">
              I've scanned the code
            </Button>
          </div>
        )}

        {step === "verify" && (
          <form onSubmit={handleVerify} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="setup-totp">Authentication Code</Label>
              <Input
                id="setup-totp"
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                placeholder="000000"
                maxLength={6}
                autoComplete="one-time-code"
                disabled={loading}
                required
              />
              <p className="text-xs text-muted-foreground">
                Enter the 6-digit code from your authenticator app
              </p>
            </div>

            {error && (
              <p className="text-sm text-destructive" role="alert">{error}</p>
            )}

            <Button type="submit" disabled={loading || totpCode.length !== 6} className="w-full">
              {loading ? "Verifying..." : "Verify & Create Account"}
            </Button>

            <button
              type="button"
              onClick={() => { setStep("qr"); setError(""); setTotpCode(""); }}
              className="w-full text-center text-xs text-muted-foreground hover:underline"
            >
              Back to QR code
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
