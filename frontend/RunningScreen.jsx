/* global React, CHECKS, CHECK_CATEGORIES, pad, fmtMs */
(function () {
const { useMemo } = React;

function RunningScreen({ results, config, sessionLabel, onCancel }) {
  // Tallies
  const tallies = useMemo(() => {
    let pass=0, warn=0, fail=0, run=0, done=0;
    for (let i = 0; i < CHECKS.length; i++) {
      const r = results[i];
      if (r === 'running') run++;
      else if (r && typeof r === 'object') {
        done++;
        if (r.status === 'pass') pass++;
        else if (r.status === 'warn') warn++;
        else fail++;
      }
    }
    return { pass, warn, fail, run, done, total: CHECKS.length };
  }, [results]);

  const pct = Math.round((tallies.done / tallies.total) * 100);
  const ringR = 60;
  const ringC = 2 * Math.PI * ringR;
  const ringDash = ringC * (1 - pct / 100);

  // current = first running, else last completed
  const currentIdx = (() => {
    for (let i = 0; i < CHECKS.length; i++) if (results[i] === 'running') return i;
    for (let i = CHECKS.length - 1; i >= 0; i--) if (results[i] && typeof results[i] === 'object') return i;
    return 0;
  })();
  const current = CHECKS[currentIdx];

  const remaining = tallies.total - tallies.done;
  const eta = remaining > 0 ? Math.max(1, Math.round(remaining * 0.35)) : 0;

  // category tallies
  const cats = useMemo(() => {
    return CHECK_CATEGORIES.map(c => {
      const idxs = CHECKS.map((ch, i) => ({ ch, i })).filter(x => x.ch.cat === c.id);
      let p = 0, w = 0, f = 0, run = 0, done = 0;
      idxs.forEach(({ i }) => {
        const r = results[i];
        if (r === 'running') run++;
        else if (r && typeof r === 'object') {
          done++;
          if (r.status === 'pass') p++;
          else if (r.status === 'warn') w++;
          else f++;
        }
      });
      return { ...c, p, w, f, run, done, total: idxs.length };
    });
  }, [results]);

  const cellState = (i) => {
    const r = results[i];
    if (r === 'running') return 'run';
    if (!r) return '';
    return r.status;
  };

  const rowState = (i) => {
    const r = results[i];
    if (r === 'running') return 'run';
    if (!r) return 'pending';
    return r.status;
  };

  // group by category, render rows
  const groupedRows = useMemo(() => {
    const groups = CHECK_CATEGORIES.map(c => ({
      cat: c,
      items: CHECKS.map((ch, i) => ({ ch, i })).filter(x => x.ch.cat === c.id),
    }));
    return groups;
  }, []);

  const symbolFor = (s) => {
    if (s === 'pass') return '✓';
    if (s === 'warn') return '!';
    if (s === 'fail') return '✕';
    if (s === 'run') return '';
    return '';
  };

  return (
    <div className="running-pg">
      <div className="run-header">
        <div className="left">
          <span className="lab"><span className="pulse" />Running suite</span>
          <span><b>{config.endpoint.replace(/^https?:\/\//, '')}</b></span>
          <span>·</span>
          <span>{config.model}</span>
          <span>·</span>
          <span>{sessionLabel}</span>
        </div>
        <button className="cancel-btn" onClick={onCancel}>
          <span>✕</span>
          <span>Abort</span>
        </button>
      </div>

      <div className="run-grid">
        <div>
          {/* Hero summary */}
          <div className="run-summary-card">
            <div className="rs-head">
              <div className="rs-eyebrow"><span className="pulse" />Live · {tallies.done} / {tallies.total} probes</div>
              <div className="rs-eta">ETA <b>~{eta}s</b></div>
            </div>
            <div className="rs-body">
              <div className="run-ring-wrap">
                <svg className="run-ring" viewBox="0 0 140 140">
                  <defs>
                    <linearGradient id="runGrad" x1="0" y1="0" x2="1" y2="1">
                      <stop offset="0" stopColor="oklch(0.55 0.22 268)" />
                      <stop offset="1" stopColor="oklch(0.68 0.20 320)" />
                    </linearGradient>
                  </defs>
                  <circle className="track" cx="70" cy="70" r={ringR} />
                  <circle className="bar"   cx="70" cy="70" r={ringR}
                    strokeDasharray={ringC} strokeDashoffset={ringDash} />
                </svg>
                <div className="run-ring-center">
                  <div className="run-pct">{pct}<sup>%</sup></div>
                  <div className="lab">complete</div>
                </div>
              </div>
              <div className="rs-current">
                <div className="lab">Currently probing</div>
                <div className="ttl">{current?.title}</div>
                <div className="ds">{current?.desc}</div>
              </div>
              <div className="rs-tally">
                <div className="item pass"><div className="n">{tallies.pass}</div><div className="l">pass</div></div>
                <div className="item warn"><div className="n">{tallies.warn}</div><div className="l">warn</div></div>
                <div className="item fail"><div className="n">{tallies.fail}</div><div className="l">fail</div></div>
              </div>
            </div>
          </div>

          {/* Matrix */}
          <div className="matrix-card">
            <div className="matrix-head">
              <div className="ttl">Probe matrix · 85 cells</div>
              <div className="legend">
                <span className="pl"><span className="d pending" />pending</span>
                <span className="pl"><span className="d run" />probing</span>
                <span className="pl"><span className="d pass" />pass</span>
                <span className="pl"><span className="d warn" />warn</span>
                <span className="pl"><span className="d fail" />fail</span>
              </div>
            </div>
            <div className="matrix">
              {CHECKS.map((c, i) => (
                <div key={i} className={'mx-cell ' + cellState(i)} title={`${c.cat}-${pad(i+1)} · ${c.title}`} />
              ))}
            </div>
          </div>

          {/* List of probes, grouped */}
          <div className="list-card">
            <div className="lc-head">
              <span>Probe stream</span>
              <span>{tallies.run > 0 ? `${tallies.run} active` : `${tallies.done} settled`}</span>
            </div>
            <div className="lc-body">
              {groupedRows.map(g => (
                <div key={g.cat.id}>
                  <div className="run-group-h">
                    <span className="lbl">
                      <span className="code">{g.cat.id}</span>
                      <span>{g.cat.label}</span>
                    </span>
                    <span>{g.items.length} probes</span>
                  </div>
                  {g.items.map(({ ch, i }) => {
                    const state = rowState(i);
                    const r = results[i];
                    return (
                      <div key={i} className={'run-row ' + state}>
                        <span className="stat">{symbolFor(state)}</span>
                        <span className="id">{ch.cat}-{pad(i+1)}</span>
                        <span className="ttl">{ch.title}</span>
                        <span className="lat">{r && typeof r === 'object' ? fmtMs(r.latency) : '—'}</span>
                        <span className="state">{state === 'pending' ? 'queued' : state === 'run' ? 'probing' : state}</span>
                      </div>
                    );
                  })}
                </div>
              ))}
            </div>
          </div>
        </div>

        <div>
          <div className="cat-stack">
            <div className="ttl">Categories</div>
            {cats.map(c => {
              const total = c.total;
              const pp = total ? (c.p / total) * 100 : 0;
              const ww = total ? (c.w / total) * 100 : 0;
              const ff = total ? (c.f / total) * 100 : 0;
              return (
                <div key={c.id} className="row">
                  <div className="top">
                    <div className="l">
                      <span className="code">{c.id}</span>
                      <span>{c.name}</span>
                    </div>
                    <div className="ct">{c.done} / {c.total}</div>
                  </div>
                  <div className="bar">
                    <i className="p" style={{ width: pp + '%' }} />
                    <i className="w" style={{ width: ww + '%' }} />
                    <i className="f" style={{ width: ff + '%' }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

window.RunningScreen = RunningScreen;
})();
