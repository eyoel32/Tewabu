const attempts = new Map(); // swap for Redis in production (multi-instance safe)

function recordFailure(key) {
  const entry = attempts.get(key) || { count: 0, first: Date.now() };
  entry.count++;
  attempts.set(key, entry);
  return entry.count;
}

function isLocked(key, max = 5, windowMs = 15 * 60 * 1000) {
  const entry = attempts.get(key);
  if (!entry) return false;
  if (Date.now() - entry.first > windowMs) {
    attempts.delete(key); // window expired, reset
    return false;
  }
  return entry.count >= max;
}

function clearAttempts(key) {
  attempts.delete(key);
}

module.exports = { recordFailure, isLocked, clearAttempts };