// Timing of the reconnect loop and the liveness ping, in a module of its own so tests can change it.
export const clock = {
  /** call fn after ms; returns a function that cancels it. kind: 'backoff', 'ping' or 'deadline' (for tests) */
  timer (ms, fn, kind) { const t = setTimeout(fn, ms); return () => clearTimeout(t) },
  /** ping the node this often ... */
  pingMs: 15000,
  /** ... and count it gone if no answer comes within this */
  pingWaitMs: 10000,
  /** one reconnect attempt (dial, membership, subscription) gets this long, then it is abandoned */
  attemptMs: 30000
}
