/* global React, ReactDOM, CHECKS, CHECK_CATEGORIES, synthResult, sessionId, SetupScreen, RunningScreen, ReportScreen, HistoryScreen, LeaderboardScreen, SEED_HISTORY */
(function () {
const { useState, useEffect, useRef, useMemo } = React;

function App() {
  const [tab, setTab] = useState('home'); // home | history | leaderboard
  const [phase, setPhase] = useState('setup'); // setup | running | report
  const [config, setConfig] = useState(null);
  const [results, setResults] = useState({});
  const [session, setSession] = useState(() => sessionId());
  const [startedAt, setStartedAt] = useState(0);
  const [durationMs, setDurationMs] = useState(0);
  const [history, setHistory] = useState(() => SEED_HISTORY.slice());
  const timersRef = useRef([]);

  const begin = (cfg) => {
    timersRef.current.forEach(clearTimeout);
    timersRef.current = [];
    setConfig(cfg);
    setResults({});
    setSession(sessionId());
    const t0 = Date.now();
    setStartedAt(t0);
    setPhase('running');
    setTab('home');

    CHECKS.forEach((check, idx) => {
      const startDelay = 80 + idx * 30 + Math.random() * 50;
      timersRef.current.push(setTimeout(() => {
        setResults(p => ({ ...p, [idx]: 'running' }));
      }, startDelay));
      const endDelay = startDelay + 220 + Math.random() * 500;
      timersRef.current.push(setTimeout(() => {
        setResults(p => ({ ...p, [idx]: synthResult(check, idx) }));
      }, endDelay));
    });

    const totalDur = 80 + CHECKS.length * 30 + 800;
    timersRef.current.push(setTimeout(() => {
      setDurationMs(Date.now() - t0);
      setPhase('report');
    }, totalDur));
  };

  const cancel = () => {
    timersRef.current.forEach(clearTimeout);
    timersRef.current = [];
    setPhase('setup');
    setResults({});
  };

  const reset = () => {
    // archive current run before resetting
    if (config) {
      let pass=0, warn=0, fail=0;
      for (let i = 0; i < CHECKS.length; i++) {
        const r = results[i];
        if (r && typeof r === 'object') {
          if (r.status === 'pass') pass++;
          else if (r.status === 'warn') warn++;
          else fail++;
        }
      }
      const score = Math.round((pass + warn * 0.5) / CHECKS.length * 100);
      const verdict = fail > 0 || score < 80 ? 'fail' : warn > 2 || score < 92 ? 'warn' : 'pass';
      setHistory(h => [{
        id: session,
        endpoint: config.endpoint.replace(/^https?:\/\//, ''),
        model: config.model,
        score, verdict, pass, warn, fail,
        when: 'Just now',
        dur: (durationMs/1000).toFixed(1) + 's',
      }, ...h].slice(0, 12));
    }
    timersRef.current.forEach(clearTimeout);
    timersRef.current = [];
    setResults({});
    setPhase('setup');
  };

  useEffect(() => () => timersRef.current.forEach(clearTimeout), []);

  const tallies = useMemo(() => {
    let pass=0, warn=0, fail=0;
    for (let i = 0; i < CHECKS.length; i++) {
      const r = results[i];
      if (r && r !== 'running') {
        if (r.status === 'pass') pass++;
        else if (r.status === 'warn') warn++;
        else fail++;
      }
    }
    return { pass, warn, fail, total: CHECKS.length };
  }, [results]);

  const catTallies = useMemo(() => {
    const m = {};
    CHECK_CATEGORIES.forEach(c => m[c.id] = { pass:0, warn:0, fail:0, total:0 });
    CHECKS.forEach((c, i) => {
      m[c.cat].total++;
      const r = results[i];
      if (r && typeof r === 'object') m[c.cat][r.status]++;
    });
    return m;
  }, [results]);

  const score = tallies.pass + tallies.warn + tallies.fail > 0
    ? Math.round((tallies.pass + tallies.warn * 0.5) / tallies.total * 100)
    : 0;
  const verdict = tallies.fail > 0 || score < 80 ? 'fail'
    : tallies.warn > 2 || score < 92 ? 'warn'
    : 'pass';

  // tab counts in nav
  const navCounts = {
    home: phase === 'running' ? '·' : '',
    history: history.length,
    leaderboard: window.LEADERBOARD?.length || 0,
  };

  return (
    <div className="app-shell">
      <nav className="app-nav">
        <div className="brand-mark">
          <div className="glyph">R</div>
          <span>Router Diag <span className="ver">v1.4</span></span>
        </div>
        <div className="nav-tabs">
          <button className={'nav-tab' + (tab === 'home' ? ' on' : '')} onClick={() => setTab('home')}>
            <span>Diagnostic</span>
            {phase === 'running' && <span className="ct" style={{ background: 'var(--accent)' }}>live</span>}
          </button>
          <button className={'nav-tab' + (tab === 'history' ? ' on' : '')} onClick={() => setTab('history')}>
            <span>History</span>
            <span className="ct">{history.length}</span>
          </button>
          <button className={'nav-tab' + (tab === 'leaderboard' ? ' on' : '')} onClick={() => setTab('leaderboard')}>
            <span>Leaderboard</span>
          </button>
        </div>
        <div className="nav-right">
          <span className="meta-pill"><span className="d" />all systems nominal</span>
        </div>
      </nav>

      <div className="app-page">
        {tab === 'home' && phase === 'setup' && <SetupScreen onStart={begin} />}
        {tab === 'home' && phase === 'running' && config && (
          <RunningScreen results={results} config={config} sessionLabel={session} onCancel={cancel} />
        )}
        {tab === 'home' && phase === 'report' && config && (
          <ReportScreen
            results={results}
            score={score}
            verdict={verdict}
            tallies={tallies}
            catTallies={catTallies}
            config={config}
            sessionLabel={session}
            durationMs={durationMs}
            onReset={reset}
          />
        )}
        {tab === 'history' && (
          <HistoryScreen history={history} onNew={() => { setTab('home'); setPhase('setup'); }} />
        )}
        {tab === 'leaderboard' && <LeaderboardScreen />}
      </div>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
})();
