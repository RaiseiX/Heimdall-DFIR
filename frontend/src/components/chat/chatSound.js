let ctx = null;

function audioContext() {
  if (ctx && ctx.state !== 'closed') return ctx;
  const Ctor = typeof window !== 'undefined' ? (window.AudioContext || window.webkitAudioContext) : null;
  ctx = Ctor ? new Ctor() : null;
  return ctx;
}

export function playPing() {
  try {
    const c = audioContext();
    if (!c) return;
    if (c.state === 'suspended' && typeof c.resume === 'function') c.resume();
    const osc = c.createOscillator();
    const gain = c.createGain();
    osc.connect(gain);
    gain.connect(c.destination);
    osc.frequency.value = 880;
    gain.gain.setValueAtTime(0.25, c.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, c.currentTime + 0.4);
    osc.onended = () => { osc.disconnect(); gain.disconnect(); };
    osc.start();
    osc.stop(c.currentTime + 0.4);
  } catch (_e) {}
}

export function releaseAudio() {
  if (ctx && ctx.state !== 'closed') ctx.close().catch(() => {});
  ctx = null;
}
