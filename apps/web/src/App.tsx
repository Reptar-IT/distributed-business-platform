import { useEffect, useState } from "react";
import { Building2, Users, ShieldCheck, LogIn, LogOut } from "lucide-react";

interface AuthSession {
  user: { id: string; displayName: string };
  csrfToken: string;
  expiresAt: number;
  isPlatformOwner: boolean;
}

interface IdentityLinkConfirmation {
  platformUserId: string;
  issuer: string;
  csrfToken: string;
}

const apiBaseUrl = (import.meta.env.VITE_API_BASE_URL ?? "http://localhost:3001").replace(/\/$/, "");

function App() {
  const [session, setSession] = useState<AuthSession | null>(null);
  const [loadingSession, setLoadingSession] = useState(true);
  const [authMessage, setAuthMessage] = useState("");
  const [loggingOut, setLoggingOut] = useState(false);
  const [identityLinkId, setIdentityLinkId] = useState("");
  const [identityLinkConfirmation, setIdentityLinkConfirmation] = useState<IdentityLinkConfirmation | null>(null);
  const [identityLinkMessage, setIdentityLinkMessage] = useState("");
  const [identityLinkBusy, setIdentityLinkBusy] = useState(false);
  const [recoveryKitCodes, setRecoveryKitCodes] = useState<string[]>([]);
  const [recoveryKitGeneration, setRecoveryKitGeneration] = useState<number | null>(null);
  const [recoveryKitReplaced, setRecoveryKitReplaced] = useState(false);
  const [recoveryKitBusy, setRecoveryKitBusy] = useState(false);
  const [recoveryKitMessage, setRecoveryKitMessage] = useState("");
  const [ownerRecoveryMessage, setOwnerRecoveryMessage] = useState("");

  useEffect(() => {
    const authResult = new URLSearchParams(window.location.search).get("auth");
    const identityLinkResult = new URLSearchParams(window.location.search).get("identity_link");
    if (authResult === "denied") setAuthMessage("Your platform account is not eligible to sign in.");
    if (authResult === "failed") setAuthMessage("Sign-in could not be completed. Please try again.");
    if (authResult === "unavailable") setAuthMessage("Authentication service is unavailable. Please try again later.");
    if (identityLinkResult === "failed") setIdentityLinkMessage("Identity linking could not be completed.");
    if (identityLinkResult === "cancelled") setIdentityLinkMessage("Identity linking was cancelled. No account was changed.");
    const recoveryResult = new URLSearchParams(window.location.search).get("owner_recovery");
    if (recoveryResult === "processing") setOwnerRecoveryMessage("Recovery identity proof was accepted. The new identity remains unavailable until archive qualification completes.");
    if (recoveryResult === "failed") setOwnerRecoveryMessage("Owner recovery could not be completed. Check the recovery operation status from the trusted CLI.");

    const confirmationMatch = /^#identity-link-confirmation\/([A-Za-z0-9_-]{43})$/.exec(window.location.hash);
    if (confirmationMatch) {
      const confirmationId = confirmationMatch[1]!;
      setIdentityLinkId(confirmationId);
      window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
      fetch(`${apiBaseUrl}/api/v1/auth/identity-link/confirmation/${confirmationId}`, {
        credentials: "include",
        cache: "no-store",
      })
        .then(async (response) => {
          if (!response.ok) throw new Error("Confirmation expired or unavailable");
          setIdentityLinkConfirmation((await response.json()) as IdentityLinkConfirmation);
        })
        .catch(() => setIdentityLinkMessage("This identity-link confirmation expired or is unavailable. No account was changed."));
    }

    const controller = new AbortController();
    fetch(`${apiBaseUrl}/api/v1/auth/session`, {
      credentials: "include",
      cache: "no-store",
      signal: controller.signal,
    })
      .then(async (response) => {
        if (response.status === 401) return null;
        if (!response.ok) throw new Error("Session check failed");
        return (await response.json()) as AuthSession;
      })
      .then((currentSession) => setSession(currentSession))
      .catch(() => setAuthMessage((message) => message || "Authentication service is unavailable."))
      .finally(() => setLoadingSession(false));

    return () => controller.abort();
  }, []);

  const respondToIdentityLink = async (decision: "confirm" | "cancel") => {
    if (!identityLinkConfirmation || !identityLinkId || identityLinkBusy) return;
    setIdentityLinkBusy(true);
    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/auth/identity-link/confirmation`, {
        method: "POST",
        credentials: "include",
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          confirmationId: identityLinkId,
          csrfToken: identityLinkConfirmation.csrfToken,
          decision,
        }),
      });
      if (!response.ok) throw new Error("Confirmation was rejected");
      const result = (await response.json()) as { outcome: "linked" | "cancelled" | "rejected" };
      setIdentityLinkConfirmation(null);
      setIdentityLinkMessage(result.outcome === "linked"
        ? "The authenticated identity was linked to the selected platform account."
        : result.outcome === "cancelled"
          ? "Identity linking was cancelled. No account was changed."
          : "Identity linking was rejected. No account was changed.");
    } catch {
      setIdentityLinkMessage("Identity linking could not be completed. No account was changed.");
    } finally {
      setIdentityLinkBusy(false);
    }
  };

  const issueRecoveryKit = async () => {
    if (!session?.isPlatformOwner || recoveryKitBusy) return;
    setRecoveryKitBusy(true);
    setRecoveryKitCodes([]);
    setRecoveryKitGeneration(null);
    setRecoveryKitMessage("");
    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/auth/owner/recovery-kit`, {
        method: "POST",
        credentials: "include",
        cache: "no-store",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": session.csrfToken },
        body: "{}",
      });
      if (!response.ok) throw new Error("Recovery kit was rejected");
      const result = (await response.json()) as { generation: number; replaced: boolean; codes: string[] };
      if (!Number.isInteger(result.generation) || result.codes.length !== 10) throw new Error("Recovery kit response was invalid");
      setRecoveryKitGeneration(result.generation);
      setRecoveryKitReplaced(result.replaced);
      setRecoveryKitCodes(result.codes);
      setRecoveryKitMessage(result.replaced
        ? "Previous unused recovery codes are invalid. Store this replacement kit now; it will not be shown again."
        : "Store this recovery kit now; it will not be shown again.");
    } catch {
      setRecoveryKitMessage("The recovery kit could not be issued. Confirm your active owner session and try again.");
    } finally {
      setRecoveryKitBusy(false);
    }
  };

  const startLogin = () => {
    window.location.assign(`${apiBaseUrl}/api/v1/auth/login`);
  };

  const logout = async () => {
    if (!session) return;
    setLoggingOut(true);
    setAuthMessage("");
    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/auth/logout`, {
        method: "POST",
        credentials: "include",
        headers: { "x-csrf-token": session.csrfToken },
      });
      if (!response.ok) throw new Error("Logout failed");
      const result = (await response.json()) as { logoutUrl: string };
      window.location.assign(result.logoutUrl);
    } catch {
      setAuthMessage("Sign-out could not be completed. Please try again.");
      setLoggingOut(false);
    }
  };

  return (
    <main className="app">
      <header className="header">
        <div className="brand">
          <Building2 size={28} />
          <span>Distributed Business Platform</span>
        </div>
        <span className="version">Platform v0.1.0</span>
      </header>

      <section className="auth-bar" aria-live="polite">
        {loadingSession ? (
          <span className="auth-status">Checking sign-in status…</span>
        ) : session ? (
          <>
            <span className="auth-status">Signed in as {session.user.displayName}</span>
            <button className="auth-button secondary" onClick={logout} disabled={loggingOut}>
              <LogOut size={17} aria-hidden="true" />
              {loggingOut ? "Signing out…" : "Sign out"}
            </button>
          </>
        ) : (
          <button className="auth-button" onClick={startLogin}>
            <LogIn size={17} aria-hidden="true" />
            Sign in
          </button>
        )}
      </section>
      {ownerRecoveryMessage && <p className="auth-message" role="status">{ownerRecoveryMessage}</p>}
      {authMessage && <p className="auth-message" role="status">{authMessage}</p>}
      {session?.isPlatformOwner && (
        <section className="owner-recovery-kit" aria-live="polite">
          <h2>Owner recovery kit</h2>
          <p>Issue or replace the ten single-use codes for recovering access to this existing owner account.</p>
          <button className="auth-button secondary" onClick={() => void issueRecoveryKit()} disabled={recoveryKitBusy}>
            {recoveryKitBusy ? "Issuing kit…" : recoveryKitCodes.length > 0 || recoveryKitReplaced ? "Replace recovery kit" : "Issue recovery kit"}
          </button>
          {recoveryKitMessage && <p role="status">{recoveryKitMessage}</p>}
          {recoveryKitCodes.length === 10 && (
            <>
              <p>Kit generation {recoveryKitGeneration}. Each code works once. Store these outside DBP; they cannot be recovered from the platform.</p>
              <ol className="owner-recovery-codes">{recoveryKitCodes.map((code) => <li key={code}><code>{code}</code></li>)}</ol>
            </>
          )}
        </section>
      )}
      {identityLinkId && (
        <section className="identity-link-confirmation" aria-live="polite">
          <h1>Confirm identity link</h1>
          {identityLinkConfirmation ? (
            <>
              <p>You just authenticated with <strong>{identityLinkConfirmation.issuer}</strong>.</p>
              <p>Do you want to link that identity to this existing DBP account?</p>
              <p className="identity-link-account">PlatformUser ID: <code>{identityLinkConfirmation.platformUserId}</code></p>
              <p>Confirm only if this is the account you intended. This does not grant platform-owner authority.</p>
              <div className="identity-link-actions">
                <button className="auth-button" onClick={() => void respondToIdentityLink("confirm")} disabled={identityLinkBusy}>
                  {identityLinkBusy ? "Submitting…" : "Confirm link"}
                </button>
                <button className="auth-button secondary" onClick={() => void respondToIdentityLink("cancel")} disabled={identityLinkBusy}>
                  Cancel
                </button>
              </div>
            </>
          ) : (
            <p role="status">{identityLinkMessage || "Loading the account confirmation…"}</p>
          )}
        </section>
      )}
      {!identityLinkId && identityLinkMessage && <p className="identity-link-message" role="status">{identityLinkMessage}</p>}

      <section className="hero">
        <p className="eyebrow">A new model of business ownership</p>
        <h1>Build businesses.<br />Share ownership.<br />Work collectively.</h1>
        <p className="description">
          An international platform for creating, managing and operating
          independent workforce-participatory businesses.
        </p>
      </section>

      <section className="principles">
        <article>
          <Building2 size={24} />
          <h2>Independent ventures</h2>
          <p>Build and operate businesses with defined commercial models and teams.</p>
        </article>

        <article>
          <Users size={24} />
          <h2>Workforce participation</h2>
          <p>Recognize verified contributions through transparent ownership policies.</p>
        </article>

        <article>
          <ShieldCheck size={24} />
          <h2>Protected governance</h2>
          <p>Enforce platform-wide safeguards and clearly defined authority.</p>
        </article>
      </section>

      <footer>
        <span>Platform foundation</span>
        <span>Development environment</span>
      </footer>
    </main>
  );
}

export default App;
