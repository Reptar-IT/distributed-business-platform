import { useEffect, useState } from "react";
import { Building2, Users, ShieldCheck, LogIn, LogOut } from "lucide-react";

interface AuthSession {
  user: { id: string; displayName: string };
  csrfToken: string;
  expiresAt: number;
}

const apiBaseUrl = (import.meta.env.VITE_API_BASE_URL ?? "http://localhost:3001").replace(/\/$/, "");

function App() {
  const [session, setSession] = useState<AuthSession | null>(null);
  const [loadingSession, setLoadingSession] = useState(true);
  const [authMessage, setAuthMessage] = useState("");
  const [loggingOut, setLoggingOut] = useState(false);

  useEffect(() => {
    const authResult = new URLSearchParams(window.location.search).get("auth");
    if (authResult === "denied") setAuthMessage("Your platform account is not eligible to sign in.");
    if (authResult === "failed") setAuthMessage("Sign-in could not be completed. Please try again.");
    if (authResult === "unavailable") setAuthMessage("Authentication service is unavailable. Please try again later.");

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
      {authMessage && <p className="auth-message" role="status">{authMessage}</p>}

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
