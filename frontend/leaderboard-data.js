/* global window */
/* Mock leaderboard + history data */
window.LEADERBOARD = [
  { rank: 1, name: 'OpenAI',     endpoint: 'api.openai.com/v1',         icon: 'openai', score: 99, verdict: 'pass', latency: 412, delta: 1,  spark: [70,75,72,78,82,80,85,88,92,95,99] },
  { rank: 2, name: 'Anthropic',  endpoint: 'api.anthropic.com/v1',      icon: 'anth',   score: 97, verdict: 'pass', latency: 488, delta: 2,  spark: [60,65,68,72,75,80,85,88,92,95,97] },
  { rank: 3, name: 'Groq',       endpoint: 'api.groq.com/openai/v1',    icon: 'groq',   score: 95, verdict: 'pass', latency: 184, delta: 4,  spark: [50,55,60,65,72,78,82,86,90,93,95] },
  { rank: 4, name: 'Together AI',endpoint: 'api.together.xyz/v1',       icon: 'together', score: 92, verdict: 'pass', latency: 521, delta: -1, spark: [80,85,88,90,93,92,90,91,93,92,92] },
  { rank: 5, name: 'Azure OpenAI', endpoint: 'oai.azure.com/v1',        icon: 'azure',  score: 91, verdict: 'pass', latency: 602, delta: 0,  spark: [88,90,89,91,90,92,91,90,91,91,91] },
  { rank: 6, name: 'DeepSeek',   endpoint: 'api.deepseek.com/v1',       icon: 'deeps',  score: 89, verdict: 'warn', latency: 712, delta: 3,  spark: [60,62,68,72,76,80,82,85,86,88,89] },
  { rank: 7, name: 'Fireworks',  endpoint: 'api.fireworks.ai/v1',       icon: 'fire',   score: 87, verdict: 'warn', latency: 396, delta: 1,  spark: [70,72,75,78,80,83,85,86,86,87,87] },
  { rank: 8, name: 'OpenRouter', endpoint: 'openrouter.ai/api/v1',      icon: 'openr',  score: 84, verdict: 'warn', latency: 845, delta: -2, spark: [88,90,89,87,86,85,84,84,85,84,84] },
  { rank: 9, name: 'Local llama.cpp', endpoint: 'localhost:8080/v1',    icon: 'local',  score: 71, verdict: 'fail', latency: 1320, delta: 8,  spark: [50,52,55,58,60,62,65,67,69,70,71] },
];

window.SEED_HISTORY = [
  { id: 'SX-3FKQ91-X8K2', endpoint: 'api.openai.com/v1',     model: 'gpt-4o-mini',          score: 99, verdict: 'pass', pass: 84, warn: 1, fail: 0, when: '2 hours ago', dur: '28.4s' },
  { id: 'SX-2HMPLX-Z2N1', endpoint: 'api.anthropic.com/v1',  model: 'claude-haiku-4-5',     score: 96, verdict: 'pass', pass: 82, warn: 3, fail: 0, when: 'Yesterday',  dur: '31.0s' },
  { id: 'SX-9KQQ0X-A3M5', endpoint: 'api.groq.com/openai/v1',model: 'llama-3.3-70b',        score: 92, verdict: 'pass', pass: 79, warn: 5, fail: 1, when: 'Yesterday',  dur: '22.6s' },
  { id: 'SX-ZZP1KY-B0N3', endpoint: 'localhost:8080/v1',     model: 'qwen2.5-coder-7b',     score: 73, verdict: 'fail', pass: 60, warn: 13, fail: 12, when: '2 days ago', dur: '40.1s' },
  { id: 'SX-LLP301-K7C2', endpoint: 'openrouter.ai/api/v1',  model: 'anthropic/claude-sonnet-4', score: 87, verdict: 'warn', pass: 75, warn: 8, fail: 2, when: '3 days ago', dur: '34.2s' },
];
