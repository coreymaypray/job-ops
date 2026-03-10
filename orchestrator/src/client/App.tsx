/**
 * Main App component.
 */

import React, { useEffect, useRef, useState } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { CSSTransition, SwitchTransition } from "react-transition-group";
import { LogOut } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Toaster } from "@/components/ui/sonner";
import { trackEvent } from "@/lib/analytics";
import { refreshAccessToken, logout } from "@client/lib/auth";
import { OnboardingGate } from "./components/OnboardingGate";
import { useDemoInfo } from "./hooks/useDemoInfo";
import { LoginPage } from "./pages/Login";
import { GmailOauthCallbackPage } from "./pages/GmailOauthCallbackPage";
import { HomePage } from "./pages/HomePage";
import { InProgressBoardPage } from "./pages/InProgressBoardPage";
import { JobPage } from "./pages/JobPage";
import { OrchestratorPage } from "./pages/OrchestratorPage";
import { SettingsPage } from "./pages/SettingsPage";
import { TracerLinksPage } from "./pages/TracerLinksPage";
import { TrackingInboxPage } from "./pages/TrackingInboxPage";
import { VisaSponsorsPage } from "./pages/VisaSponsorsPage";

/** Backwards-compatibility redirects: old URL paths -> new URL paths */
const REDIRECTS: Array<{ from: string; to: string }> = [
  { from: "/", to: "/jobs/ready" },
  { from: "/home", to: "/overview" },
  { from: "/ready", to: "/jobs/ready" },
  { from: "/ready/:jobId", to: "/jobs/ready/:jobId" },
  { from: "/discovered", to: "/jobs/discovered" },
  { from: "/discovered/:jobId", to: "/jobs/discovered/:jobId" },
  { from: "/applied", to: "/jobs/applied" },
  { from: "/applied/:jobId", to: "/jobs/applied/:jobId" },
  { from: "/in-progress", to: "/applications/in-progress" },
  { from: "/in-progress/:jobId", to: "/applications/in-progress" },
  { from: "/jobs/in_progress", to: "/applications/in-progress" },
  { from: "/jobs/in_progress/:jobId", to: "/applications/in-progress" },
  { from: "/all", to: "/jobs/all" },
  { from: "/all/:jobId", to: "/jobs/all/:jobId" },
];

export const App: React.FC = () => {
  const location = useLocation();
  const nodeRef = useRef<HTMLDivElement>(null);
  const demoInfo = useDemoInfo();

  const [authed, setAuthed] = useState(false);
  const [authChecked, setAuthChecked] = useState(false);

  useEffect(() => {
    refreshAccessToken().then((token) => {
      setAuthed(!!token);
      setAuthChecked(true);
    });
  }, []);

  // Determine a stable key for transitions to avoid unnecessary unmounts when switching sub-tabs
  const pageKey = React.useMemo(() => {
    const firstSegment = location.pathname.split("/")[1] || "jobs";
    if (firstSegment === "jobs") {
      return "orchestrator";
    }
    return firstSegment;
  }, [location.pathname]);

  const handleLogout = async () => {
    await logout();
    setAuthed(false);
  };

  if (!authChecked) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <p className="text-sm text-muted-foreground">Loading...</p>
      </div>
    );
  }

  if (!authed) {
    return <LoginPage onLogin={() => setAuthed(true)} />;
  }

  return (
    <>
      <div className="fixed right-4 top-4 z-50">
        <Button
          type="button"
          variant="ghost"
          size="icon"
          onClick={handleLogout}
          className="h-8 w-8 text-muted-foreground hover:text-foreground"
        >
          <LogOut className="h-4 w-4" />
          <span className="sr-only">Sign out</span>
        </Button>
      </div>
      <OnboardingGate />
      {demoInfo?.demoMode && (
        <div className="w-full border-b border-amber-400/50 bg-amber-500/20 px-4 py-2 text-center text-xs text-amber-100 backdrop-blur">
          Demo mode: integrations are simulated and data resets every{" "}
          {demoInfo.resetCadenceHours} hours.{" "}
          <a
            className="font-semibold underline underline-offset-2 hover:text-amber-50"
            href="https://github.com/coreymaypray/sloth-jobs"
            target="_blank"
            rel="noreferrer"
            onClick={() =>
              trackEvent("star_repo_click", { location: "demo_mode_banner" })
            }
          >
            Star the repo on GitHub
          </a>
          .
        </div>
      )}
      <div>
        <SwitchTransition mode="out-in">
          <CSSTransition
            key={pageKey}
            nodeRef={nodeRef}
            timeout={100}
            classNames="page"
            unmountOnExit
          >
            <div ref={nodeRef}>
              <Routes location={location}>
                {/* Backwards-compatibility redirects */}
                {REDIRECTS.map(({ from, to }) => (
                  <Route
                    key={from}
                    path={from}
                    element={<Navigate to={to} replace />}
                  />
                ))}

                {/* Application routes */}
                <Route path="/overview" element={<HomePage />} />
                <Route
                  path="/oauth/gmail/callback"
                  element={<GmailOauthCallbackPage />}
                />
                <Route path="/job/:id" element={<JobPage />} />
                <Route
                  path="/applications/in-progress"
                  element={<InProgressBoardPage />}
                />
                <Route path="/settings" element={<SettingsPage />} />
                <Route path="/tracer-links" element={<TracerLinksPage />} />
                <Route path="/visa-sponsors" element={<VisaSponsorsPage />} />
                <Route path="/tracking-inbox" element={<TrackingInboxPage />} />
                <Route path="/jobs/:tab" element={<OrchestratorPage />} />
                <Route
                  path="/jobs/:tab/:jobId"
                  element={<OrchestratorPage />}
                />
              </Routes>
            </div>
          </CSSTransition>
        </SwitchTransition>
      </div>

      <Toaster position="bottom-right" richColors closeButton />
    </>
  );
};
