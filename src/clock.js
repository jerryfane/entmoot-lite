// Timing of the reconnect loop and the liveness ping, in a module of its own so tests can change it.
export const clock = {
  /** wait between reconnect attempts */
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  /** ping the node this often ... */
  pingMs: 15000,
  /** ... and count it gone if no answer comes within this */
  pingWaitMs: 10000
}
