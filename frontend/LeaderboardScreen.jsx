/* global React, LEADERBOARD */
(function () {

function LeaderboardScreen() {
  const data = window.LEADERBOARD || [];
  const top = data[0] || { score: 0 };
  const avg = data.length ? Math.round(data.reduce((s, x) => s + x.score, 0) / data.length) : 0;
  const passing = data.filter(x => x.verdict === 'pass').length;

  // category strip per provider — synth from rank
  const catStrip = (rank) => {
    const map = ['p100','p100','p100','p80','p100','p100','p80','p100'];
    if (rank === 1) return ['p100','p100','p100','p100','p100','p100','p100','p100'];
    if (rank === 2) return ['p100','p100','p100','p80','p100','p100','p100','p100'];
    if (rank === 3) return ['p100','p100','p100','p100','warn','p100','p80','p100'];
    if (rank === 4) return ['p100','p100','p100','p100','p80','p80','p100','p80'];
    if (rank === 5) return ['p100','p100','p100','p80','p100','p80','p80','warn'];
    if (rank === 6) return ['p100','p100','warn','p80','p100','warn','p80','warn'];
    if (rank === 7) return ['p100','warn','p100','p80','warn','p100','p80','p80'];
    if (rank === 8) return ['p100','p80','warn','p80','warn','warn','warn','warn'];
    if (rank === 9) return ['p80','warn','warn','warn','fail','fail','warn','fail'];
    return map;
  };

  return (
    <div className="page-pg">
      <div className="page-head">
        <div>
          <h1>Provider leaderboard</h1>
          <div className="desc">Public conformance rankings across major OpenAI-compatible endpoints. Updated continuously from community-submitted runs.</div>
        </div>
        <div className="actions">
          <button className="btn-ghost">Methodology</button>
          <button className="btn-dark">Submit run →</button>
        </div>
      </div>

      <div className="lb-stats">
        <div className="tile">
          <div className="k">Top score</div>
          <div className="v">{top.score}<sup>/100</sup></div>
          <div className="d">{top.name} · {top.endpoint}</div>
        </div>
        <div className="tile">
          <div className="k">Median score</div>
          <div className="v">{avg}<sup>/100</sup></div>
          <div className="d">across {data.length} providers tracked</div>
        </div>
        <div className="tile">
          <div className="k">Passing the bar</div>
          <div className="v">{passing}<sup>/{data.length}</sup></div>
          <div className="d">≥ 90 score · zero fails</div>
        </div>
        <div className="tile">
          <div className="k">Last refreshed</div>
          <div className="v">2<sup>m ago</sup></div>
          <div className="d">12,847 community runs · 7d window</div>
        </div>
      </div>

      <div className="lb-table">
        <div className="h">
          <span>#</span>
          <span>PROVIDER</span>
          <span style={{ textAlign: 'right' }}>SCORE</span>
          <span>VERDICT</span>
          <span className="lat" style={{ textAlign: 'right' }}>p50 LAT</span>
          <span className="cats">CATEGORIES</span>
          <span>7-DAY TREND</span>
        </div>
        {data.map(p => (
          <div key={p.name} className="lb-row">
            <span className={'lb-rank ' + (p.rank <= 3 ? 'r' + p.rank : '')}>{p.rank}</span>
            <div className="lb-prov">
              <div className={'icon ' + p.icon}>{p.name.split(' ').map(s => s[0]).slice(0,2).join('').toUpperCase()}</div>
              <div>
                <div className="nm">{p.name}</div>
                <div className="endpoint">{p.endpoint}</div>
              </div>
            </div>
            <div className="lb-score" style={{ textAlign: 'right' }}>
              {p.score}<sup>/100</sup>
            </div>
            <span className={'lb-tag ' + p.verdict}><span className="d" />{p.verdict}</span>
            <div className="lb-lat" style={{ textAlign: 'right' }}>
              {p.latency}<sup>ms</sup>
            </div>
            <div className="lb-cats">
              {catStrip(p.rank).map((c, i) => <i key={i} className={c} />)}
            </div>
            <div className="lb-trend">
              <span className={'delta ' + (p.delta > 0 ? 'up' : p.delta < 0 ? 'down' : 'flat')}>
                {p.delta > 0 ? '▲' : p.delta < 0 ? '▼' : '—'} {Math.abs(p.delta) || 0}
              </span>
              <span className="spark">
                {p.spark.map((v, i) => (
                  <i key={i} className={i >= p.spark.length - 3 ? 'hi' : ''} style={{ height: Math.max(2, v / 100 * 22) + 'px' }} />
                ))}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

window.LeaderboardScreen = LeaderboardScreen;
})();
