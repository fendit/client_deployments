import { useState, useRef, useEffect } from 'react'
import type { KeyboardEvent, ClipboardEvent } from 'react'
import { Activate } from '../wailsjs/go/main/App'
import { Quit, EventsOn } from '../wailsjs/runtime/runtime'

// ActivationResult mirrors app.go ActivationResult struct.
interface ActivationResult {
  success: boolean
  error?: string
}

type Phase = 'input' | 'installing' | 'success' | 'error' | 'fda'

export default function App() {
  const [digits, setDigits] = useState<string[]>(Array(6).fill(''))
  const [phase, setPhase] = useState<Phase>('input')
  const [phaseMsg, setPhaseMsg] = useState('Connecting to Fendit cloud...')
  const [errorMsg, setErrorMsg] = useState('')
  const inputs = useRef<(HTMLInputElement | null)[]>([])

  const code = digits.join('')
  const ready = code.length === 6

  // Subscribe to progress events emitted by app.go → runtime.EventsEmit(ctx, "phase", msg)
  useEffect(() => {
    EventsOn('phase', (msg: string) => setPhaseMsg(msg))
  }, [])

  function handleChange(i: number, raw: string) {
    const char = raw.replace(/\D/g, '').slice(-1)
    const next = [...digits]
    next[i] = char
    setDigits(next)
    if (char && i < 5) inputs.current[i + 1]?.focus()
  }

  function handleKey(i: number, e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Backspace' && !digits[i] && i > 0) {
      inputs.current[i - 1]?.focus()
    }
  }

  function handlePaste(e: ClipboardEvent<HTMLInputElement>) {
    e.preventDefault()
    const raw = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6)
    const next = Array(6).fill('')
    for (let i = 0; i < raw.length; i++) next[i] = raw[i]
    setDigits(next)
    inputs.current[Math.min(raw.length, 5)]?.focus()
  }

  async function handleActivate() {
    if (!ready) return
    setPhase('installing')
    setErrorMsg('')

    const result: ActivationResult = await Activate(code)
    if (result.success) {
      setPhase('success')
      setTimeout(() => Quit(), 3000)
    } else if (result.error === 'fda_required') {
      setPhase('fda')
    } else {
      setErrorMsg(result.error ?? 'Installation failed. Please try again.')
      setPhase('error')
    }
  }

  return (
    <div className="flex flex-col h-screen bg-[#0f0f18] text-white select-none overflow-hidden">

      {/* ── Title bar / drag region ───────────────────────────────────────── */}
      <div
        className="flex items-center justify-between px-5 h-9 shrink-0 border-b border-white/[0.06]"
        style={{ '--wails-draggable': 'drag' } as React.CSSProperties}
      >
        <span className="text-[11px] font-medium tracking-[0.18em] text-white/25 uppercase">
          Fendit Security
        </span>
        <button
          onClick={() => Quit()}
          className="w-5 h-5 rounded flex items-center justify-center text-white/25 hover:text-white/80 hover:bg-white/10 transition-colors text-[11px] leading-none"
          style={{ '--wails-draggable': 'no-drag' } as React.CSSProperties}
        >
          ✕
        </button>
      </div>

      {/* ── Main content ─────────────────────────────────────────────────── */}
      <div className="flex flex-col flex-1 items-center justify-center px-10 gap-9">

        {/* Icon */}
        <div className={`w-[72px] h-[72px] rounded-2xl flex items-center justify-center transition-colors duration-700 ${
          phase === 'success'
            ? 'bg-emerald-500/15 ring-1 ring-emerald-500/30'
            : phase === 'fda'
            ? 'bg-amber-500/15 ring-1 ring-amber-500/30'
            : 'bg-blue-600/15 ring-1 ring-blue-600/30'
        }`}>
          {phase === 'success' ? (
            <svg className="w-9 h-9 text-emerald-400" viewBox="0 0 24 24" fill="none"
              stroke="currentColor" strokeWidth={2.5} strokeLinecap="round" strokeLinejoin="round">
              <polyline points="20 6 9 17 4 12" />
            </svg>
          ) : phase === 'fda' ? (
            <svg className="w-9 h-9 text-amber-400" viewBox="0 0 24 24" fill="none"
              stroke="currentColor" strokeWidth={1.75} strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <line x1="12" y1="10" x2="12" y2="14" strokeWidth={2.5} strokeLinecap="round" />
              <circle cx="12" cy="17" r="0.5" fill="currentColor" strokeWidth={2} />
            </svg>
          ) : phase === 'installing' ? (
            <div className="w-7 h-7 border-2 border-blue-400 border-t-transparent rounded-full animate-spin" />
          ) : (
            <svg className="w-9 h-9 text-blue-400" viewBox="0 0 24 24" fill="none"
              stroke="currentColor" strokeWidth={1.75} strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          )}
        </div>

        {/* Heading + subtitle */}
        <div className="text-center -mt-2">
          <h1 className="text-[17px] font-semibold tracking-tight">
            {phase === 'success'
              ? 'Device Protected'
              : phase === 'fda'
              ? 'Action Required: Apple Security'
              : 'Activate Fendit Security'}
          </h1>
          <p className="text-sm text-white/40 mt-1.5 leading-snug">
            {phase === 'input' || phase === 'error'
              ? 'Enter the 6-digit code from your organization admin.'
              : phase === 'success'
              ? 'Closing in a moment...'
              : phase === 'fda'
              ? 'A system window has opened — follow the steps below.'
              : phaseMsg}
          </p>
        </div>

        {/* ── State: code input ─────────────────────────────────────────── */}
        {(phase === 'input' || phase === 'error') && (
          <>
            <div className="flex gap-3">
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
                    'w-11 h-[54px] text-center text-[22px] font-mono rounded-lg',
                    'bg-white/[0.04] border transition-all duration-150',
                    'outline-none caret-transparent',
                    phase === 'error' && !d
                      ? 'border-red-500/50 focus:border-red-400'
                      : 'border-white/10 focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30',
                  ].join(' ')}
                />
              ))}
            </div>

            {phase === 'error' && errorMsg && (
              <p className="text-[12px] text-red-400/80 text-center -mt-5 max-w-[260px] leading-relaxed">
                {errorMsg}
              </p>
            )}

            <button
              onClick={handleActivate}
              disabled={!ready}
              className={[
                'w-full py-3 rounded-lg text-[14px] font-medium transition-all duration-150',
                ready
                  ? 'bg-blue-600 hover:bg-blue-500 active:scale-[0.985] cursor-pointer'
                  : 'bg-white/[0.04] text-white/20 cursor-not-allowed',
              ].join(' ')}
            >
              {phase === 'error' ? 'Try Again' : 'Install & Activate'}
            </button>
          </>
        )}

        {/* ── State: installing ─────────────────────────────────────────── */}
        {phase === 'installing' && (
          <p className="text-[13px] text-white/35 animate-pulse -mt-2">{phaseMsg}</p>
        )}

        {/* ── State: fda — guide the user through the macOS privacy prompt ── */}
        {phase === 'fda' && (
          <div className="flex flex-col items-center gap-5 w-full -mt-2">
            <ol className="text-[12.5px] text-white/50 leading-relaxed space-y-2 self-start w-full">
              <li className="flex gap-2.5">
                <span className="text-amber-400 font-semibold shrink-0">1.</span>
                <span>
                  In the window that opened, find{' '}
                  <span className="text-white/80 font-medium">Fendit Security</span> in the list.
                </span>
              </li>
              <li className="flex gap-2.5">
                <span className="text-amber-400 font-semibold shrink-0">2.</span>
                <span>
                  Toggle it{' '}
                  <span className="text-emerald-400 font-semibold">ON</span>
                  {' '}and enter your Mac password if prompted.
                </span>
              </li>
              <li className="flex gap-2.5">
                <span className="text-amber-400 font-semibold shrink-0">3.</span>
                <span>Click the button below to continue.</span>
              </li>
            </ol>
            <button
              onClick={handleActivate}
              className="w-full py-3 rounded-lg text-[14px] font-medium bg-amber-500 hover:bg-amber-400 active:scale-[0.985] cursor-pointer transition-all duration-150 text-black"
            >
              Check Again / Continue
            </button>
          </div>
        )}

        {/* ── State: success — no extra content, icon + heading say it all ── */}

      </div>

      {/* ── Footer ───────────────────────────────────────────────────────── */}
      <div className="h-8 shrink-0 flex items-center justify-center">
        <span className="text-[11px] text-white/[0.12]">
          © {new Date().getFullYear()} Fendit B.V.
        </span>
      </div>
    </div>
  )
}
