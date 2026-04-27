/* global React, CHECKS, CHECK_CATEGORIES, PRESETS */
(function () {
const { useState } = React;

function SetupScreen({ onStart }) {
  const [presetIdx, setPresetIdx] = useState(0);
  const p = PRESETS[presetIdx];
  const [endpoint, setEndpoint] = useState(p.endpoint);
  const [apiKey, setApiKey]     = useState('sk-proj-6f9c2****8b3a');
  const [model, setModel]       = useState(p.model);
  const [mode, setMode]         = useState('full');

  const choose = (i) => {
    setPresetIdx(i);
    setEndpoint(PRESETS[i].endpoint);
    setModel(PRESETS[i].model);
  };

  const start = () => {
    if (!endpoint || !model) return;
    onStart({ endpoint, apiKey, model, mode });
  };

  // Brief check counts per category (mock)
  const briefCount = mode === 'brief' ? 18 : mode === 'compat' ? 32 : 85;

  return (
    <div className="home">
      <div className="home-hero">
        <div className="home-eyebrow">
          <span className="pulse" />
          <span>Endpoint Diagnostics</span>
          <span className="badge">v1.4</span>
        </div>
        <h1 className="home-title">
          Verify any LLM endpoint<br/>
          <em>across 85 conformance probes.</em>
        </h1>
        <p className="home-sub">
          A single suite to validate connectivity, OpenAI-schema conformance,
          streaming, tool-calling, context recall, and performance — for any
          OpenAI-compatible router.
        </p>
      </div>

      <div className="form-card">
        <div className="form-card-head">
          <div className="l">
            <span className="step">1</span>
            <span>Configure target endpoint</span>
          </div>
          <div className="r">~ {Math.round(briefCount * 0.35)}s suite</div>
        </div>
        <div className="form-body">
          <div className="presets-row">
            {PRESETS.map((pp, i) => (
              <button key={pp.name} className={'preset-chip' + (i === presetIdx ? ' on' : '')} onClick={() => choose(i)}>
                <span className="dt" />
                <span>{pp.name}</span>
              </button>
            ))}
          </div>

          <div className="field-block">
            <div className="field-label">
              <span className="l">Endpoint</span>
              <span className="h">POST /v1/chat/completions</span>
            </div>
            <div className="input">
              <span className="pre">https://</span>
              <input type="text" className="mono"
                value={endpoint.replace(/^https?:\/\//, '')}
                onChange={e => setEndpoint('https://' + e.target.value)}
                placeholder="api.example.com/v1" />
              <span className="post"><span className="d" />reachable</span>
            </div>
          </div>

          <div className="field-row">
            <div className="field-block" style={{ marginBottom: 0 }}>
              <div className="field-label">
                <span className="l">API key</span>
                <span className="h">stored in session memory</span>
              </div>
              <div className="input">
                <span className="pre">Bearer</span>
                <input type="password" className="mono" value={apiKey}
                  onChange={e => setApiKey(e.target.value)} placeholder="sk-..." />
              </div>
            </div>
            <div className="field-block" style={{ marginBottom: 0 }}>
              <div className="field-label">
                <span className="l">Model</span>
                <span className="h">used in probe payloads</span>
              </div>
              <div className="input">
                <input type="text" className="mono" value={model}
                  onChange={e => setModel(e.target.value)} placeholder="gpt-4o-mini" />
              </div>
            </div>
          </div>

          <div className="field-block" style={{ marginTop: 18, marginBottom: 0 }}>
            <div className="field-label">
              <span className="l">Suite</span>
              <span className="h">{briefCount} checks · {mode === 'full' ? '~30s' : mode === 'compat' ? '~14s' : '~7s'}</span>
            </div>
            <div className="mode-seg">
              <button className={'mode-card' + (mode === 'brief' ? ' on' : '')} onClick={() => setMode('brief')}>
                <span className="mt">18</span>
                <div className="mn">Brief</div>
                <div className="md">smoke test</div>
              </button>
              <button className={'mode-card' + (mode === 'compat' ? ' on' : '')} onClick={() => setMode('compat')}>
                <span className="mt">32</span>
                <div className="mn">OpenAI compat</div>
                <div className="md">schema + streaming</div>
              </button>
              <button className={'mode-card' + (mode === 'full' ? ' on' : '')} onClick={() => setMode('full')}>
                <span className="mt">85</span>
                <div className="mn">Full suite</div>
                <div className="md">conformance + perf</div>
              </button>
            </div>
          </div>

          <div className="form-foot">
            <div className="foot-hint">
              Press <span className="kbd">⏎</span> to run · <span className="kbd">esc</span> to cancel
            </div>
            <button className="btn-primary" onClick={start} disabled={!endpoint || !model}>
              <span>Start diagnostic</span>
              <span className="arrow">→</span>
            </button>
          </div>
        </div>
      </div>

      <div className="cat-strip">
        {CHECK_CATEGORIES.map(c => {
          const ct = CHECKS.filter(x => x.cat === c.id).length;
          return (
            <div key={c.id} className="cat-tile">
              <div className="ic">{c.id}</div>
              <div className="nm">{c.name}</div>
              <div className="ct">{ct} probes</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

window.SetupScreen = SetupScreen;
})();
