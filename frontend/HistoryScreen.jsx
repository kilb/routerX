/* global React, SEED_HISTORY, CHECKS */
(function () {
const { useMemo } = React;

function HistoryScreen({ history, onOpen, onNew }) {
  // mock matrix per row deterministically
  const matrices = useMemo(() => {
    return (history || []).map(h => {
      const total = (h.pass||0) + (h.warn||0) + (h.fail||0);
      const out = [];
      for (let i = 0; i < total; i++) {
        if (i < h.pass) out.push('p');
        else if (i < h.pass + h.warn) out.push('w');
        else out.push('f');
      }
      // shuffle deterministically
      let seed = total;
      for (let i = out.length - 1; i > 0; i--) {
        seed = (seed * 9301 + 49297) % 233280;
        const j = Math.floor((seed / 233280) * (i + 1));
        [out[i], out[j]] = [out[j], out[i]];
      }
      return out;
    });
  }, [history]);

  const empty = !history || history.length === 0;

  return (
    <div className="page-pg">
      <div className="page-head">
        <div>
          <h1>Recent diagnostics</h1>
          <div className="desc">Every suite you've run, scored against the conformance bar. Click a row to revisit the full report.</div>
        </div>
        <div className="actions">
          <button className="btn-ghost">Export CSV</button>
          <button className="btn-dark" onClick={onNew}>+ New diagnostic</button>
        </div>
      </div>

      {empty && (
        <div className="empty-state">
          <div className="ic">⌕</div>
          <h3>No diagnostics yet</h3>
          <p>Run your first conformance suite — results will be archived here for comparison.</p>
          <button className="btn-dark" onClick={onNew}>Start a diagnostic →</button>
        </div>
      )}

      {!empty && (
        <div className="history-list">
          {history.map((h, i) => (
            <div key={h.id} className="hist-card" onClick={() => onOpen && onOpen(h)}>
              <div className={'score-pip ' + h.verdict}>
                <div className="n">{h.score}</div>
                <div className="l">{h.verdict}</div>
              </div>
              <div className="info">
                <div className="t1">{h.endpoint} <span style={{ color: 'var(--ink-4)', fontWeight: 400 }}>·</span> {h.model}</div>
                <div className="t2">
                  <span>{h.id}</span>
                  <span className="sep">·</span>
                  <span style={{ color: 'var(--pass)' }}>{h.pass} pass</span>
                  <span style={{ color: 'var(--warn)' }}>{h.warn} warn</span>
                  <span style={{ color: 'var(--fail)' }}>{h.fail} fail</span>
                </div>
              </div>
              <div className="mini-mtx">
                {matrices[i].map((c, j) => (
                  <i key={j} className={c} />
                ))}
              </div>
              <div className="ts">
                <b>{h.when}</b>
                <div style={{ marginTop: 2 }}>{h.dur}</div>
              </div>
              <div className="chev">›</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

window.HistoryScreen = HistoryScreen;
})();
