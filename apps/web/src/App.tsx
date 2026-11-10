import { Building2, Users, ShieldCheck } from "lucide-react";

function App() {
  return (
    <main className="app">
      <header className="header">
        <div className="brand">
          <Building2 size={28} />
          <span>Distributed Business Platform</span>
        </div>
        <span className="version">Platform v0.1.0</span>
      </header>

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
