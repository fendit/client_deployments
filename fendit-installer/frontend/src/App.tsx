import { useState, useRef, useEffect } from 'react'
import type { KeyboardEvent, ClipboardEvent } from 'react'
import { Activate } from '../wailsjs/go/main/App'
import { Quit, EventsOn } from '../wailsjs/runtime/runtime'

interface ActivationResult {
  success: boolean
  error?: string
}

type Phase = 'input' | 'installing' | 'success' | 'error' | 'fda'

const STEPS = [
  'Connecting to Fendit cloud...',
  'Downloading security components...',
  'Removing previous installation...',
  'Installing security agent...',
  'Registering with security cloud...',
  'Finalising setup...',
  'Activating protection...',
]

// ── Icons ─────────────────────────────────────────────────────────────────────

function ShieldIcon({ className = '' }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" className={className}
      stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  )
}

function CheckIcon({ className = '' }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" className={className}
      stroke="currentColor" strokeWidth={2.5} strokeLinecap="round" strokeLinejoin="round">
      <polyline points="20 6 9 17 4 12" />
    </svg>
  )
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function App() {
  const [digits, setDigits] = useState<string[]>(Array(6).fill(''))
  const [phase, setPhase] = useState<Phase>('input')
  const [stepIdx, setStepIdx] = useState(0)
  const [phaseMsg, setPhaseMsg] = useState(STEPS[0])
  const [errorMsg, setErrorMsg] = useState('')
  const [countdown, setCountdown] = useState(3)
  const inputs = useRef<(HTMLInputElement | null)[]>([])
  const countdownRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const code = digits.join('')
  const ready = code.length === 6
  const progress = Math.round(((stepIdx + 1) / STEPS.length) * 100)

  useEffect(() => {
    EventsOn('phase', (msg: string) => {
      setPhaseMsg(msg)
      const i = STEPS.indexOf(msg)
      if (i >= 0) setStepIdx(i)
    })
  }, [])

  useEffect(() => {
    if (phase !== 'success') return
    countdownRef.current = setInterval(() => {
      setCountdown(c => {
        if (c <= 1) { clearInterval(countdownRef.current!); Quit(); return 0 }
        return c - 1
      })
    }, 1000)
    return () => { if (countdownRef.current) clearInterval(countdownRef.current) }
  }, [phase])

  function handleChange(i: number, raw: string) {
    const char = raw.replace(/\D/g, '').slice(-1)
    const next = [...digits]
    next[i] = char
    setDigits(next)
    if (char && i < 5) inputs.current[i + 1]?.focus()
  }

  function handleKey(i: number, e: KeyboardEvent<HTMLInputElement>) {
    if (e.key !== 'Backspace') return
    e.preventDefault()
    if (digits[i]) {
      const next = [...digits]; next[i] = ''; setDigits(next)
    } else if (i > 0) {
      const next = [...digits]; next[i - 1] = ''; setDigits(next)
      inputs.current[i - 1]?.focus()
    }
  }

  function handlePaste(e: ClipboardEvent<HTMLInputElement>) {
    e.preventDefault()
    const raw = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6)
    const next = Array(6).fill('')
    for (let j = 0; j < raw.length; j++) next[j] = raw[j]
    setDigits(next)
    inputs.current[Math.min(raw.length, 5)]?.focus()
  }

  async function handleActivate() {
    if (!ready) return
    setPhase('installing')
    setStepIdx(0)
    setPhaseMsg(STEPS[0])
    setErrorMsg('')

    const result: ActivationResult = await Activate(code)
    if (result.success) {
      setPhase('success')
      setCountdown(3)
    } else if (result.error === 'fda_required') {
      setPhase('fda')
    } else {
      setErrorMsg(result.error ?? 'Installation failed. Please try again.')
      setPhase('error')
    }
  }

  return (
    <div className="flex flex-col h-screen bg-[#090912] text-white select-none overflow-hidden">

      {/* ── Title bar ───────────────────────────────────────────────────────── */}
      <div
        className="flex items-center justify-between px-5 h-10 shrink-0 border-b border-white/[0.05]"
        style={{ '--wails-draggable': 'drag' } as React.CSSProperties}
      >
        <div className="flex items-center gap-2">
          <ShieldIcon className="w-3.5 h-3.5 text-[#4f8eff] opacity-70" />
          <span className="text-[10.5px] font-semibold tracking-[0.22em] text-white/25 uppercase">
            Fendit Security
          </span>
        </div>
        <button
          onClick={() => Quit()}
          style={{ '--wails-draggable': 'no-drag' } as React.CSSProperties}
          className="w-5 h-5 flex items-center justify-center rounded text-white/20 hover:text-white/60 hover:bg-white/[0.06] transition-all duration-100 text-[11px] leading-none"
        >
          ✕
        </button>
      </div>

      {/* ── Body ────────────────────────────────────────────────────────────── */}
      <div className="flex flex-col flex-1 min-h-0 items-center justify-center px-9 gap-7">

        {/* ── INPUT / ERROR ── */}
        {(phase === 'input' || phase === 'error') && (
          <>
            {/* Icon */}
            <div className="relative">
              <div className="w-[78px] h-[78px] rounded-[22px] flex items-center justify-center bg-[#4f8eff]/[0.08] ring-1 ring-[#4f8eff]/[0.18]">
                <ShieldIcon className="w-10 h-10 text-[#4f8eff]" />
              </div>
              {phase === 'error' && (
                <span className="absolute -top-1 -right-1 w-5 h-5 rounded-full bg-red-500 border-2 border-[#090912] flex items-center justify-center text-[9px] font-bold leading-none">
                  !
                </span>
              )}
            </div>

            {/* Heading */}
            <div className="text-center space-y-1.5">
              <h1 className="text-[17px] font-semibold tracking-tight">
                {phase === 'error' ? 'Activation Failed' : 'Activate Protection'}
              </h1>
              <p className="text-[13px] text-white/40 leading-snug">
                {phase === 'error'
                  ? 'Correct the error below and try again.'
                  : 'Enter your 6-digit code from your IT administrator.'}
              </p>
            </div>

            {/* Code inputs */}
            <div className="flex gap-2.5">
              {digits.map((d, i) => (
                <input
                  key={i}
                  ref={el => { inputs.current[i] = el }}
                  type="text"
                  inputMode="numeric"
                  maxLength={1}
                  value={d}
                  autoFocus={i === 0}
                  onChange={e => handleChange(i, e.target.value)}
                  onKeyDown={e => handleKey(i, e)}
                  onPaste={handlePaste}
                  className={[
                    'w-11 h-[54px] text-center text-[22px] font-mono font-semibold rounded-xl',
                    'border outline-none caret-transparent transition-all duration-150',
                    phase === 'error' && !d
                      ? 'bg-red-500/[0.05] border-red-500/40 text-red-300 focus:border-red-500/70'
                      : d
                      ? 'bg-[#4f8eff]/[0.07] border-[#4f8eff]/40'
                      : 'bg-white/[0.035] border-white/[0.07] focus:border-[#4f8eff]/60 focus:bg-[#4f8eff]/[0.04] focus:ring-1 focus:ring-[#4f8eff]/20',
                  ].join(' ')}
                />
              ))}
            </div>

            {/* Error message */}
            {phase === 'error' && errorMsg && (
              <p className="text-[11.5px] text-red-400/80 text-center -mt-3 max-w-[270px] leading-relaxed">
                {errorMsg}
              </p>
            )}

            {/* CTA button */}
            <button
              onClick={handleActivate}
              disabled={!ready}
              className={[
                'w-full py-3.5 rounded-xl text-[14px] font-semibold transition-all duration-150',
                ready
                  ? 'bg-[#4f8eff] hover:bg-[#6b9fff] active:scale-[0.985] cursor-pointer shadow-[0_4px_24px_rgba(79,142,255,0.22)]'
                  : 'bg-white/[0.04] text-white/20 cursor-not-allowed',
              ].join(' ')}
            >
              {phase === 'error' ? 'Try Again' : 'Activate & Install'}
            </button>
          </>
        )}

        {/* ── INSTALLING ── */}
        {phase === 'installing' && (
          <>
            {/* Animated icon */}
            <div className="w-[78px] h-[78px] rounded-[22px] flex items-center justify-center bg-[#4f8eff]/[0.08] ring-1 ring-[#4f8eff]/[0.18] relative">
              <ShieldIcon className="w-10 h-10 text-[#4f8eff]/25 absolute" />
              <div className="w-6 h-6 border-[2.5px] border-[#4f8eff] border-t-transparent rounded-full animate-spin" />
            </div>

            <div className="text-center space-y-1.5">
              <h1 className="text-[17px] font-semibold tracking-tight">Installing Fendit…</h1>
              <p className="text-[13px] text-white/40 transition-all duration-300">{phaseMsg}</p>
            </div>

            {/* Progress */}
            <div className="w-full space-y-2">
              <div className="flex justify-between text-[11px] text-white/20">
                <span>Step {stepIdx + 1} of {STEPS.length}</span>
                <span>{progress}%</span>
              </div>
              <div className="w-full h-[3px] bg-white/[0.06] rounded-full overflow-hidden">
                <div
                  className="h-full bg-[#4f8eff] rounded-full transition-all duration-500 ease-out"
                  style={{ width: `${progress}%` }}
                />
              </div>
              <div className="flex gap-1 pt-0.5">
                {STEPS.map((_, i) => (
                  <div
                    key={i}
                    className={[
                      'h-1 rounded-full flex-1 transition-all duration-400',
                      i < stepIdx
                        ? 'bg-[#4f8eff]'
                        : i === stepIdx
                        ? 'bg-[#4f8eff]/60 animate-pulse'
                        : 'bg-white/[0.07]',
                    ].join(' ')}
                  />
                ))}
              </div>
            </div>
          </>
        )}

        {/* ── FDA ── */}
        {phase === 'fda' && (
          <>
            {/* Icon */}
            <div className="w-[78px] h-[78px] rounded-[22px] flex items-center justify-center bg-amber-500/[0.08] ring-1 ring-amber-500/[0.2]">
              <svg viewBox="0 0 24 24" fill="none" className="w-10 h-10 text-amber-400"
                stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                <line x1="12" y1="9" x2="12" y2="13.5" strokeWidth={2.2} />
                <circle cx="12" cy="16.8" r="0.65" fill="currentColor" stroke="none" />
              </svg>
            </div>

            <div className="text-center space-y-1.5">
              <h1 className="text-[17px] font-semibold tracking-tight">One More Step</h1>
              <p className="text-[13px] text-white/40 leading-snug">
                macOS requires your permission<br />to enable full disk monitoring.
              </p>
            </div>

            {/* Numbered instructions card */}
            <div className="w-full rounded-xl border border-white/[0.07] bg-white/[0.02] p-4 space-y-3.5">
              {[
                <>Find <span className="text-white font-medium">Fendit Security</span> in the window that just opened.</>,
                <>Toggle it <span className="font-semibold text-emerald-400">ON</span> and confirm with your Mac password if asked.</>,
                <>Click <span className="text-white font-medium">Check Again</span> below to continue.</>,
              ].map((content, i) => (
                <div key={i} className="flex items-start gap-3">
                  <div className="shrink-0 w-[21px] h-[21px] rounded-full bg-amber-500/[0.1] border border-amber-500/25 flex items-center justify-center mt-px">
                    <span className="text-[10px] font-bold text-amber-400">{i + 1}</span>
                  </div>
                  <p className="text-[12.5px] text-white/50 leading-snug pt-0.5">{content}</p>
                </div>
              ))}
            </div>

            <button
              onClick={handleActivate}
              className="w-full py-3.5 rounded-xl text-[14px] font-semibold bg-amber-500 hover:bg-amber-400 active:scale-[0.985] cursor-pointer transition-all duration-150 text-black shadow-[0_4px_20px_rgba(245,158,11,0.18)]"
            >
              Check Again / Continue
            </button>
          </>
        )}

        {/* ── SUCCESS ── */}
        {phase === 'success' && (
          <>
            <div className="w-[78px] h-[78px] rounded-[22px] flex items-center justify-center bg-emerald-500/[0.08] ring-1 ring-emerald-500/[0.2]">
              <CheckIcon className="w-10 h-10 text-emerald-400" />
            </div>

            <div className="text-center space-y-1.5">
              <h1 className="text-[17px] font-semibold tracking-tight">Protection Active</h1>
              <p className="text-[13px] text-white/40 leading-snug">
                Your device is now monitored<br />by Fendit Security.
              </p>
            </div>

            {/* Status badge */}
            <div className="w-full rounded-xl border border-emerald-500/[0.15] bg-emerald-500/[0.05] px-4 py-3 flex items-center gap-3">
              <div className="w-2 h-2 rounded-full bg-emerald-400 shrink-0 animate-pulse" />
              <span className="text-[12px] text-emerald-400/80 leading-snug">
                Real-time monitoring active · All interceptors engaged
              </span>
            </div>

            <p className="text-[11.5px] text-white/20 -mt-1">
              Closing in {countdown} second{countdown !== 1 ? 's' : ''}…
            </p>
          </>
        )}

      </div>

      {/* ── Footer ──────────────────────────────────────────────────────────── */}
      <div className="h-9 shrink-0 border-t border-white/[0.04] flex items-center justify-center">
        <span className="text-[10px] text-white/[0.12] tracking-wide">
          © {new Date().getFullYear()} Fendit B.V. · Enterprise Security
        </span>
      </div>

    </div>
  )
}
