/* global React, CHECKS, CHECK_CATEGORIES, pad, fmtMs */
(function () {
const { useState, useMemo, useEffect } = React;

function ReportScreen({ results, score, verdict, tallies, catTallies, config, sessionLabel, durationMs, onReset }) {
  const [filter, setFilter] = useState('all'); // all | pass | warn | fail
  const [catFilter, setCatFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [openIdx, setOpenIdx] = useState(null);

  const items = useMemo(() => {
    return CHECKS.map((ch, i) => {
      const r = results[i];
      return r && typeof r === 'object'
        ? { ...r, ch, i, idLabel: ch.cat + '-' + pad(i + 1) }
        : { ch, i, idLabel: ch.cat + '-' + pad(i + 1), status: 'pass', latency: 0, req: '', resp: '', note: '' };
    });
  }, [results]);

  const filtered = useMemo(() => items.filter(it => {
    if (filter !== 'all' && it.status !== filter) return false;
    if (catFilter !== 'all' && it.ch.cat !== catFilter) return false;
    if (search && !(it.ch.title.toLowerCase().includes(search.toLowerCase()) || it.idLabel.toLowerCase().includes(search.toLowerCase()))) return false;
    return true;
  }), [items, filter, catFilter, search]);

  const issues = useMemo(() => items.filter(x => x.status === 'fail' || x.status === 'warn').sort((a,b) => a.status === b.status ? 0 : a.status === 'fail' ? -1 : 1).slice(0, 5), [items]);

  // metrics
  const latencies = items.map(x => x.latency).filter(Boolean).sort((a,b) => a-b);
  const p50 = latencies.length ? latencies[Math.floor(latencies.length * 0.5)] : 0;
  const p95 = latencies.length ? latencies[Math.floor(latencies.length * 0.95)] : 0;
  const avgTok = 47;
  const ttft = 380;

  // Score ring math
  const scoreR = 52;
  const scoreC = 2 * Math.PI * scoreR;
  const scoreDash = scoreC * (1 - score / 100);

  // Sparkline data (mock latency dist)
  const spark = useMemo(() => {
    const buckets = new Array(20).fill(0);
    items.forEach(x => {
      if (!x.latency) return;
      const idx = Math.min(19, Math.floor(x.latency / 150));
      buckets[idx]++;
    });
    const max = Math.max(...buckets, 1);
    return buckets.map(b => b / max);
  }, [items]);

  const opened = openIdx != null ? items[openIdx] : null;
  useEffect(() => {
    if (opened == null) return;
    const onKey = (e) => {
      if (e.key === 'Escape') setOpenIdx(null);
      if (e.key === 'ArrowDown' && openIdx < CHECKS.length - 1) setOpenIdx(openIdx + 1);
      if (e.key === 'ArrowUp' && openIdx > 0) setOpenIdx(openIdx - 1);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [opened, openIdx]);

  // Radar chart data — score per category
  const radarData = useMemo(() => {
    return CHECK_CATEGORIES.map(c => {
      const t = catTallies[c.id];
      const pct = t.total ? Math.round((t.pass + t.warn * 0.5) / t.total * 100) : 0;
      return { ...c, pct };
    });
  }, [catTallies]);

  // build SVG radar polygon
  const radarPath = useMemo(() => {
    const cx = 130, cy = 130, R = 100;
    const n = radarData.length;
    return radarData.map((d, i) => {
      const ang = (Math.PI * 2 * i) / n - Math.PI / 2;
      const r = R * (d.pct / 100);
      return `${cx + Math.cos(ang) * r},${cy + Math.sin(ang) * r}`;
    }).join(' ');
  }, [radarData]);
  const radarLabels = useMemo(() => {
    const cx = 130, cy = 130, R = 116;
    return radarData.map((d, i) => {
      const ang = (Math.PI * 2 * i) / radarData.length - Math.PI / 2;
      return { x: cx + Math.cos(ang) * R, y: cy + Math.sin(ang) * R, code: d.id, pct: d.pct };
    });
  }, [radarData]);
  const radarRings = [25, 50, 75, 100];

  // category bar data sorted by score
  const catBars = useMemo(() => {
    return CHECK_CATEGORIES.map(c => {
      const t = catTallies[c.id];
      const pct = t.total ? Math.round((t.pass + t.warn * 0.5) / t.total * 100) : 0;
      return { ...c, ...t, pct };
    }).sort((a,b) => b.pct - a.pct);
  }, [catTallies]);

  const symbolFor = (s) => s === 'pass' ? '✓' : s === 'warn' ? '!' : s === 'fail' ? '✕' : '·';

  return (
    <div className="report-pg">
      <div className="rep-head">
        <div className="left">
          <div className="crumb">
            <span>Session</span>
            <b>{sessionLabel}</b>
            <span>·</span>
            <b>{config.endpoint.replace(/^https?:\/\//,'')}</b>
            <span>·</span>
            <b>{config.model}</b>
          </div>
        </div>
        <div className="rep-actions">
          <button className="btn-ghost">Export JSON</button>
          <button className="btn-ghost">Share report</button>
          <button className="btn-dark" onClick={onReset}>Run again →</button>
        </div>
      </div>

      <div className="bento">
        {/* hero verdict — compact banner row */}
        <div className={'tile dark verdict ' + verdict}>
          <div className="visual-rays" />
          <div className="v-row">
            <div className="v-left">
              <div className="v-eyebrow"><span className="d" />
                {verdict === 'pass' ? 'All systems nominal' : verdict === 'warn' ? 'Conditional pass' : 'Action required'}
              </div>
              <h1>
                {verdict === 'pass'
                  ? <>Endpoint conforms — <em>ready for traffic.</em></>
                  : verdict === 'warn'
                    ? <>Endpoint <em>mostly conforms</em>, with caveats.</>
                    : <>Endpoint has <em>conformance gaps</em> blocking production.</>
                }
              </h1>
              <div className="meta">
                <span><b>{tallies.total}</b> checks</span>
                <span>· <b>{(durationMs/1000).toFixed(1)}s</b> wall</span>
                <span>· <b>{config.mode || 'full'}</b> suite</span>
                <span>· <b>p50 {fmtMs(p50)}</b></span>
              </div>
            </div>
            <div className="score-ring">
              <svg viewBox="0 0 120 120">
                <defs>
                  <linearGradient id="scoreGrad" x1="0" y1="0" x2="1" y2="1">
                    <stop offset="0" stopColor="oklch(0.78 0.18 268)" />
                    <stop offset="1" stopColor="oklch(0.85 0.15 200)" />
                  </linearGradient>
                </defs>
                <circle className="track" cx="60" cy="60" r={scoreR} />
                <circle className="bar"   cx="60" cy="60" r={scoreR}
                  strokeDasharray={scoreC} strokeDashoffset={scoreDash}
                  transform="rotate(-90 60 60)" />
              </svg>
              <div className="ctr"><div className="n">{score}</div><div className="l">score</div></div>
            </div>
            <div className="v-tally">
              <div className="vt-item pass"><div className="n">{tallies.pass}</div><div className="l">pass</div></div>
              <div className="vt-item warn"><div className="n">{tallies.warn}</div><div className="l">warn</div></div>
              <div className="vt-item fail"><div className="n">{tallies.fail}</div><div className="l">fail</div></div>
            </div>
          </div>
        </div>

        {/* metric tiles */}
        <div className="tile metric">
          <div className="k">p50 latency</div>
          <div className="v">{fmtMs(p50)}</div>
          <div className="d">across {latencies.length} probes · target &lt; 1.5s</div>
          <div className="spark">
            {spark.slice(0, 14).map((v, i) => (
              <i key={i} className={i < 7 ? 'hi' : ''} style={{ height: Math.max(3, v*28) + 'px' }} />
            ))}
          </div>
        </div>

        <div className="tile metric">
          <div className="k">p95 latency</div>
          <div className="v">{fmtMs(p95)}</div>
          <div className="d">tail · budget 4.0s</div>
          <div className="spark">
            {spark.slice(6).map((v, i) => (
              <i key={i} className={i > 8 ? 'hi' : ''} style={{ height: Math.max(3, v*28) + 'px' }} />
            ))}
          </div>
        </div>

        <div className="tile metric">
          <div className="k">First-token</div>
          <div className="v">{ttft}<sup>ms</sup></div>
          <div className="d">streaming TTFT · {avgTok} tok/s sustained</div>
          <div className="spark">
            {[0.4,0.6,0.5,0.7,0.8,0.6,0.5,0.55,0.6,0.7,0.65,0.62,0.7,0.75].map((v,i) => (
              <i key={i} className={v > 0.6 ? 'hi' : ''} style={{ height: Math.max(3, v*28) + 'px' }} />
            ))}
          </div>
        </div>

        {/* Radar */}
        <div className="tile radar">
          <div className="ttl">Conformance radar</div>
          <div className="desc">Per-category coverage · 0 → 100</div>
          <svg viewBox="0 0 260 260">
            {radarRings.map(r => (
              <polygon key={r} points={radarData.map((_, i) => {
                const ang = (Math.PI * 2 * i) / radarData.length - Math.PI / 2;
                const rr = (100 * r) / 100;
                return `${130 + Math.cos(ang) * rr},${130 + Math.sin(ang) * rr}`;
              }).join(' ')}
                fill="none" stroke="oklch(0.91 0.005 80)" strokeWidth="1" />
            ))}
            {radarData.map((_, i) => {
              const ang = (Math.PI * 2 * i) / radarData.length - Math.PI / 2;
              return <line key={i} x1="130" y1="130"
                x2={130 + Math.cos(ang) * 100} y2={130 + Math.sin(ang) * 100}
                stroke="oklch(0.91 0.005 80)" strokeWidth="1" />;
            })}
            <polygon points={radarPath}
              fill="oklch(0.55 0.22 268 / 0.18)"
              stroke="oklch(0.55 0.22 268)" strokeWidth="2"
              strokeLinejoin="round" />
            {radarData.map((d, i) => {
              const ang = (Math.PI * 2 * i) / radarData.length - Math.PI / 2;
              const r = 100 * (d.pct / 100);
              return <circle key={i} cx={130 + Math.cos(ang) * r} cy={130 + Math.sin(ang) * r}
                r="3.5" fill="oklch(0.55 0.22 268)" />;
            })}
            {radarLabels.map((l, i) => (
              <g key={i}>
                <text x={l.x} y={l.y} textAnchor="middle" dominantBaseline="middle"
                  fontFamily="'Geist Mono', monospace" fontSize="10" fontWeight="600"
                  fill="oklch(0.36 0.010 270)">{l.code}</text>
                <text x={l.x} y={l.y + 12} textAnchor="middle" dominantBaseline="middle"
                  fontFamily="'Geist Mono', monospace" fontSize="9"
                  fill="oklch(0.55 0.008 270)">{l.pct}%</text>
              </g>
            ))}
          </svg>
        </div>

        {/* Category bars */}
        <div className="tile catbars">
          <div className="h">
            <div className="ttl">Category breakdown</div>
            <div className="sub">sorted by score</div>
          </div>
          {catBars.map(c => (
            <div className="cb-row" key={c.id}>
              <div className="code">{c.id}</div>
              <div className="nm">{c.name}</div>
              <div className="bar">
                <i className="p" style={{ width: c.total ? (c.pass / c.total * 100) + '%' : 0 }} />
                <i className="w" style={{ width: c.total ? (c.warn / c.total * 100) + '%' : 0 }} />
                <i className="f" style={{ width: c.total ? (c.fail / c.total * 100) + '%' : 0 }} />
              </div>
              <div className="pct">{c.pct}<sup style={{fontSize:10,color:'var(--ink-3)'}}>%</sup></div>
            </div>
          ))}
        </div>

        {/* Issues */}
        <div className="tile issues">
          <div className="h">
            <div className="ttl">Top issues</div>
            <div className="sub">{tallies.fail} fail · {tallies.warn} warn</div>
          </div>
          {issues.length === 0 && (
            <div style={{ padding: '20px 0', textAlign: 'center', color: 'var(--ink-3)', fontSize: 13 }}>
              No issues detected ✓
            </div>
          )}
          {issues.map((it, k) => (
            <div key={k} className={'iss-row ' + it.status} onClick={() => setOpenIdx(it.i)}>
              <span className="ic">{it.status === 'fail' ? '✕' : '!'}</span>
              <div>
                <div className="iss-nm">{it.ch.title}</div>
                <div className="iss-id">{it.idLabel} · {it.ch.cat} · {fmtMs(it.latency)}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Filter controls + list */}
      <div className="rep-controls">
        <div className="grp">
          <button className={'chip' + (filter==='all' ? ' on' : '')} onClick={() => setFilter('all')}>All <span className="ct">{tallies.total}</span></button>
          <button className={'chip' + (filter==='pass' ? ' on' : '')} onClick={() => setFilter('pass')}>Pass <span className="ct">{tallies.pass}</span></button>
          <button className={'chip' + (filter==='warn' ? ' on' : '')} onClick={() => setFilter('warn')}>Warn <span className="ct">{tallies.warn}</span></button>
          <button className={'chip' + (filter==='fail' ? ' on' : '')} onClick={() => setFilter('fail')}>Fail <span className="ct">{tallies.fail}</span></button>
        </div>
        <div className="grp-sep" />
        <div className="grp">
          <button className={'chip' + (catFilter==='all' ? ' on' : '')} onClick={() => setCatFilter('all')}>All cats</button>
          {CHECK_CATEGORIES.map(c => (
            <button key={c.id} className={'chip' + (catFilter===c.id ? ' on' : '')} onClick={() => setCatFilter(c.id)}>{c.id}</button>
          ))}
        </div>
        <div className="grp-sep" />
        <div className="search">
          <span className="ic">⌕</span>
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search probes…" />
        </div>
      </div>

      <div className="check-list">
        <div className="h">
          <span></span>
          <span className="id">ID</span>
          <span>CAT</span>
          <span>PROBE</span>
          <span style={{ textAlign: 'right' }}>LATENCY</span>
          <span style={{ textAlign: 'center' }}>STATUS</span>
          <span></span>
        </div>
        {filtered.map(it => (
          <div key={it.i} className={'row ' + it.status} onClick={() => setOpenIdx(it.i)}>
            <span className="stat">{symbolFor(it.status)}</span>
            <span className="id">{it.idLabel}</span>
            <span className="cat">{it.ch.cat}</span>
            <span className="nm">{it.ch.title}</span>
            <span className="lat">{fmtMs(it.latency)}</span>
            <span className="state">{it.status}</span>
            <span className="chev">›</span>
          </div>
        ))}
        {filtered.length === 0 && (
          <div style={{ padding: '40px 20px', textAlign: 'center', color: 'var(--ink-3)' }}>
            No probes match the current filter.
          </div>
        )}
      </div>

      {/* Detail drawer */}
      <div className={'drawer-mask' + (opened ? ' on' : '')} onClick={() => setOpenIdx(null)} />
      <div className={'drawer' + (opened ? ' on' : '')}>
        {opened && (
          <>
            <div className="drawer-h">
              <div className="l">
                <span className="id-pill">{opened.idLabel}</span>
                <span className="cat-pill">{CHECK_CATEGORIES.find(c => c.id === opened.ch.cat)?.label}</span>
              </div>
              <button className="close" onClick={() => setOpenIdx(null)}>✕</button>
            </div>
            <div className="drawer-body">
              <div className={'drawer-title ' + opened.status}>
                <div className="stat-big">{symbolFor(opened.status)}</div>
                <div>
                  <h2>{opened.ch.title}</h2>
                  <div className="desc">{opened.ch.desc}</div>
                </div>
              </div>
              <div className="drawer-stats">
                <div className={'cell ' + opened.status}>
                  <div className="k">Status</div>
                  <div className="v">{opened.status}</div>
                </div>
                <div className="cell">
                  <div className="k">Latency</div>
                  <div className="v">{fmtMs(opened.latency)}</div>
                </div>
                <div className="cell">
                  <div className="k">Category</div>
                  <div className="v">{opened.ch.cat}</div>
                </div>
              </div>

              <div className="drawer-section">
                <div className="h"><span>Finding</span></div>
                <div className={'finding-card ' + opened.status}>
                  <div className="ic">{symbolFor(opened.status)}</div>
                  <div className="body">
                    <div className="k">{opened.status === 'pass' ? 'Probe satisfied' : opened.status === 'warn' ? 'Passed with caveats' : 'Probe failed'}</div>
                    <div className="v">{opened.note}</div>
                  </div>
                </div>
              </div>

              <div className="drawer-section">
                <div className="h"><span>Request</span><button className="copy">copy</button></div>
                <pre className="code-block">{opened.req}</pre>
              </div>

              <div className="drawer-section">
                <div className="h"><span>Response</span><button className="copy">copy</button></div>
                <pre className="code-block">{opened.resp}</pre>
              </div>
            </div>
            <div className="drawer-foot">
              <button className="nav-btn" disabled={openIdx === 0} onClick={() => setOpenIdx(openIdx - 1)}>← Prev</button>
              <span className="of">{openIdx + 1} of {CHECKS.length}</span>
              <button className="nav-btn" disabled={openIdx === CHECKS.length - 1} onClick={() => setOpenIdx(openIdx + 1)}>Next →</button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

window.ReportScreen = ReportScreen;
})();
