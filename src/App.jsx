import React, { useEffect, useMemo, useRef, useState } from 'react'
import firebase from 'firebase/compat/app'
import 'firebase/compat/auth'
import 'firebase/compat/firestore'
import 'firebase/compat/app-check'
import { Chart } from 'chart.js/auto'
import ChartDataLabels from 'chartjs-plugin-datalabels'

const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY || '',
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN || '',
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID || '',
  storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET || '',
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID || '',
  appId: import.meta.env.VITE_FIREBASE_APP_ID || '',
}

let auth = null
let db = null
let authPersistenceReady = Promise.resolve()
try {
  if (!firebase.apps.length) firebase.initializeApp(firebaseConfig)
  const appCheckKey = import.meta.env.VITE_RECAPTCHA_V3_SITE_KEY || ''
  if (appCheckKey) firebase.appCheck().activate(appCheckKey, false)
  auth = firebase.auth()
  authPersistenceReady = auth
    .setPersistence(firebase.auth.Auth.Persistence.LOCAL)
    .catch((error) => {
      console.warn('Persistent sign-in is unavailable on this device.', error)
    })
  db = firebase.firestore()
  db.enablePersistence({ cache: 'owning-tab' }).catch(() => {})
} catch (error) {
  console.error('Firebase initialization failed', error)
}

const ASKK_API_URL = import.meta.env.VITE_ASKK_API_URL
  || 'https://stock-stickies-askk.99redder.workers.dev/api/ask-k'
const GOOGLE_CLIENT_ID = import.meta.env.VITE_GOOGLE_CLIENT_ID
  || '896398882822-9rdud5bpkdkcg6afqhgfus2cc7loc5va.apps.googleusercontent.com'

const ACCOUNTS = [
  { id: 'individual', label: 'Individual', short: 'Taxable', strategy: 'Taxable individual brokerage — primarily swing trades and shorter-horizon positions.' },
  { id: 'traditional', label: 'Traditional IRA', short: 'Trad. IRA', strategy: 'Traditional IRA — long-term buy-and-hold core of quality names.' },
  { id: 'roth', label: 'Roth IRA', short: 'Roth IRA', strategy: 'Roth IRA — higher-risk speculative names plus cash secured puts.' },
]
const ACCOUNT_IDS = ACCOUNTS.map((account) => account.id)
const UNASSIGNED = 'unassigned'
const CHART_COLORS = ['#9ca3af', '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4', '#ec4899', '#84cc16', '#f97316']
const DONUT_MIN_SLICE_PERCENT = 4
const MAX_DONUT_STOCK_SLICES = 8

const normalizeTicker = (value) => String(value || '').trim().toUpperCase()
const getAccount = (note) => ACCOUNT_IDS.includes(note?.account) ? note.account : UNASSIGNED
const getAccountLabel = (id) => ACCOUNTS.find((account) => account.id === id)?.label || 'Unassigned'
const getPutAccount = (put) => ACCOUNT_IDS.includes(put?.account) ? put.account : 'roth'
const money = (value, digits = 0) => new Intl.NumberFormat('en-US', {
  style: 'currency',
  currency: 'USD',
  minimumFractionDigits: digits,
  maximumFractionDigits: digits,
}).format(Number(value || 0))
const number = (value, digits = 2) => Number(value || 0).toLocaleString('en-US', {
  maximumFractionDigits: digits,
})
const isCrypto = (note) => note?.plaidIsCrypto === true || note?.plaidSecurityType === 'cryptocurrency'
const plaidPrice = (note) => {
  const price = Number(note?.plaidInstitutionPrice)
  return Number.isFinite(price) && price > 0 ? price : 0
}

const friendlyAuthError = (reason) => {
  const code = reason?.code || ''
  if (['auth/invalid-credential', 'auth/wrong-password', 'auth/user-not-found'].includes(code)) {
    return 'That email or password is not correct.'
  }
  if (code === 'auth/invalid-email') return 'Enter a valid email address.'
  if (code === 'auth/too-many-requests') return 'Too many attempts. Wait a few minutes and try again.'
  if (code === 'auth/network-request-failed') return 'The connection was interrupted. Check your signal and try again.'
  if (code === 'auth/unauthorized-domain') return 'This mobile address is not yet authorized for sign-in.'
  if (code === 'auth/popup-blocked') return 'Your browser blocked Google sign-in. Please try the button again.'
  return String(reason?.message || 'Unable to sign in.')
    .replace(/^Firebase:\s*/i, '')
    .replace(/\s*\(auth\/[^)]+\)\.?$/i, '')
}

const formatDateTime = (value) => {
  if (!value) return 'Not available'
  const date = value instanceof Date ? value : new Date(value)
  if (!Number.isFinite(date.getTime())) return 'Not available'
  return new Intl.DateTimeFormat('en-US', {
    month: 'numeric',
    day: 'numeric',
    year: '2-digit',
    hour: 'numeric',
    minute: '2-digit',
  }).format(date).replace(',', ' at')
}

const formatDate = (value) => {
  if (!value) return 'Not available'
  const date = value instanceof Date ? value : new Date(value)
  if (!Number.isFinite(date.getTime())) return 'Not available'
  return new Intl.DateTimeFormat('en-US', {
    month: 'numeric',
    day: 'numeric',
    year: 'numeric',
  }).format(date)
}

async function getEncryptionKey(userId) {
  const encoder = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(`${userId}|StockStickies|2024`),
    'PBKDF2',
    false,
    ['deriveKey'],
  )
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: encoder.encode('StockStickiesSalt2024'), iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  )
}

async function decryptApiKey(value, userId) {
  if (!value) return ''
  if (typeof value === 'string') return value
  if (!value.encrypted || !value.iv || !userId) return ''
  try {
    const key = await getEncryptionKey(userId)
    const encrypted = Uint8Array.from(atob(value.encrypted), (character) => character.charCodeAt(0))
    const iv = Uint8Array.from(atob(value.iv), (character) => character.charCodeAt(0))
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encrypted)
    return new TextDecoder().decode(decrypted)
  } catch {
    return ''
  }
}

function Icon({ name, size = 20 }) {
  const paths = {
    refresh: <><path d="M20 6v5h-5" /><path d="M18.5 15a7 7 0 1 1-.5-8l2 4" /></>,
    search: <><circle cx="11" cy="11" r="7" /><path d="m20 20-4-4" /></>,
    chevron: <path d="m8 10 4 4 4-4" />,
    close: <><path d="m6 6 12 12" /><path d="m18 6-12 12" /></>,
    send: <><path d="m22 2-7 20-4-9-9-4Z" /><path d="M22 2 11 13" /></>,
    logout: <><path d="M10 17l5-5-5-5" /><path d="M15 12H3" /><path d="M21 19V5a2 2 0 0 0-2-2h-6" /></>,
    install: <><path d="M12 3v12" /><path d="m7 10 5 5 5-5" /><path d="M5 21h14" /></>,
  }
  return <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">{paths[name]}</svg>
}

function StockStickiesLogo({ compact = false }) {
  return (
    <div className={`stock-logo ${compact ? 'compact' : ''}`} aria-label="Stock Stickies">
      <svg viewBox="0 0 48 48" fill="none" aria-hidden="true">
        <rect x="2" y="2" width="44" height="44" rx="4" fill="#1a1a2e" stroke="#00ff9f" strokeWidth="2" />
        <path d="M8 32 L16 20 L22 26 L32 12 L40 18" stroke="#39ff14" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
        <circle cx="16" cy="20" r="3" fill="#39ff14" />
        <circle cx="32" cy="12" r="3" fill="#39ff14" />
        <rect x="6" y="36" width="8" height="6" fill="#39ff14" opacity=".7" />
        <rect x="16" y="33" width="8" height="9" fill="#39ff14" opacity=".8" />
        <rect x="26" y="30" width="8" height="12" fill="#39ff14" opacity=".9" />
        <rect x="36" y="34" width="6" height="8" fill="#39ff14" opacity=".6" />
      </svg>
      <span className="stock-wordmark">
        <strong>STOCK</strong>
        <span>STICKIES</span>
      </span>
    </div>
  )
}

function PortfolioDonut({ positions, total, cashValue }) {
  const canvasRef = useRef(null)
  const chartRef = useRef(null)

  useEffect(() => {
    if (!canvasRef.current || !positions.length) return undefined
    const cash = positions.filter((position) => position.isCash)
    const stocks = positions
      .filter((position) => !position.isCash)
      .sort((a, b) => b.value - a.value)
    const visibleStocks = stocks
      .filter((position) => total > 0 && (position.value / total) * 100 >= DONUT_MIN_SLICE_PERCENT)
      .slice(0, MAX_DONUT_STOCK_SLICES)
    const visibleIds = new Set(visibleStocks.map((position) => position.id))
    const smallStocks = stocks.filter((position) => !visibleIds.has(position.id))
    const slices = [
      ...(cash.length ? [{
        ticker: 'Cash',
        value: cash.reduce((sum, item) => sum + item.value, 0),
        color: '#9ca3af',
      }] : []),
      ...visibleStocks.map((position, index) => ({
        ...position,
        color: CHART_COLORS[(index + 1) % CHART_COLORS.length],
      })),
      ...(smallStocks.length ? [{
        ticker: `Other (${smallStocks.length})`,
        value: smallStocks.reduce((sum, item) => sum + item.value, 0),
        color: '#475569',
      }] : []),
    ]
    const ctx = canvasRef.current.getContext('2d')
    chartRef.current?.destroy()
    chartRef.current = new Chart(ctx, {
      type: 'doughnut',
      plugins: [ChartDataLabels],
      data: {
        labels: slices.map((slice) => slice.ticker),
        datasets: [{
          data: slices.map((slice) => slice.value),
          backgroundColor: slices.map((slice) => slice.color),
          borderColor: '#11161f',
          borderWidth: 3,
          hoverOffset: 5,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '72%',
        animation: { duration: 350 },
        plugins: {
          legend: { display: false },
          datalabels: {
            anchor: 'center',
            align: 'center',
            clamp: true,
            clip: true,
            color: '#f8fafc',
            textStrokeColor: 'rgba(8, 11, 16, .82)',
            textStrokeWidth: 3,
            font: (context) => {
              const label = String(context.chart.data.labels?.[context.dataIndex] || '')
              const value = Number(context.dataset.data?.[context.dataIndex] || 0)
              const percent = total > 0 ? (value / total) * 100 : 0
              return {
                family: 'Inter, ui-sans-serif, system-ui, sans-serif',
                size: percent < 4 || label.length > 5 ? 8 : (label.length > 3 ? 9 : 10),
                weight: '800',
              }
            },
            formatter: (_value, context) => {
              const label = String(context.chart.data.labels?.[context.dataIndex] || '')
              return label.startsWith('Other') ? 'OTHER' : label.toUpperCase()
            },
          },
          tooltip: {
            backgroundColor: '#202733',
            titleColor: '#fff',
            bodyColor: '#d9e1ec',
            padding: 12,
            callbacks: {
              label: (context) => {
                const value = Number(context.raw || 0)
                const percent = total > 0 ? (value / total) * 100 : 0
                return ` ${money(value)} · ${percent.toFixed(1)}%`
              },
            },
          },
        },
      },
    })
    return () => chartRef.current?.destroy()
  }, [positions, total])

  return (
    <div className="donut-wrap">
      <canvas ref={canvasRef} aria-label="Portfolio allocation donut chart" />
      <div className="donut-center" aria-hidden="true">
        <span>Portfolio</span>
        <strong>{money(total)}</strong>
        <small>{total > 0 ? `${((cashValue / total) * 100).toFixed(1)}% cash` : 'No priced holdings'}</small>
      </div>
    </div>
  )
}

function AskK({ portfolio }) {
  const [open, setOpen] = useState(false)
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const scrollRef = useRef(null)
  const quickPrompts = [
    'How concentrated is my portfolio?',
    'What are my largest risks?',
    'How much cash do I have by account?',
    'Review my CSP obligations.',
  ]

  useEffect(() => {
    if (open && messages.length === 0) {
      setMessages([{ role: 'assistant', content: "Hi — I'm K. Ask me about concentration, allocation, accounts, cash, or your CSP exposure." }])
    }
  }, [open, messages.length])

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' })
  }, [messages, busy])

  const send = async (raw) => {
    const text = String(raw || '').trim()
    if (!text || busy) return
    const history = [...messages, { role: 'user', content: text }]
    setMessages(history)
    setInput('')
    setBusy(true)
    try {
      const response = await fetch(ASKK_API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: text,
          history: history.slice(-10),
          portfolio,
        }),
      })
      const result = await response.json().catch(() => ({}))
      setMessages((current) => [...current, {
        role: 'assistant',
        content: result?.ok && result?.reply ? result.reply : (result?.error || 'I could not process that. Try again in a moment.'),
      }])
    } catch {
      setMessages((current) => [...current, { role: 'assistant', content: 'I cannot reach Ask K right now. Check your connection and try again.' }])
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <button className="ask-k-fab" type="button" onClick={() => setOpen(true)} aria-label="Open Ask K">
        <img src="/assets/ask-k-profile.png" alt="" /> Ask K
      </button>
      {open && <button className="scrim" type="button" aria-label="Close Ask K" onClick={() => setOpen(false)} />}
      <aside className={`ask-drawer ${open ? 'open' : ''}`} aria-hidden={!open} aria-label="Ask K portfolio assistant">
        <header className="ask-header">
          <img className="k-avatar" src="/assets/ask-k-profile.png" alt="K" />
          <div><strong>Ask K</strong><small>Portfolio analysis assistant</small></div>
          <button className="icon-button" type="button" onClick={() => setOpen(false)} aria-label="Close"><Icon name="close" /></button>
        </header>
        <div className="messages" ref={scrollRef}>
          {messages.map((message, index) => (
            <div key={`${message.role}-${index}`} className={`message ${message.role}`}>
              {message.content.split('\n').map((line, lineIndex) => <React.Fragment key={lineIndex}>{lineIndex > 0 && <br />}{line}</React.Fragment>)}
            </div>
          ))}
          {busy && <div className="message assistant thinking">K is thinking<span>…</span></div>}
          {messages.length <= 1 && !busy && (
            <div className="quick-prompts">
              {quickPrompts.map((prompt) => <button type="button" key={prompt} onClick={() => send(prompt)}>{prompt}</button>)}
            </div>
          )}
        </div>
        <form className="ask-compose" onSubmit={(event) => { event.preventDefault(); send(input) }}>
          <textarea value={input} onChange={(event) => setInput(event.target.value)} rows="1" placeholder="Ask about your portfolio…" aria-label="Message Ask K" />
          <button type="submit" disabled={busy || !input.trim()} aria-label="Send"><Icon name="send" /></button>
          <small>K provides observations, not financial advice.</small>
        </form>
      </aside>
    </>
  )
}

function ProfileSheet({
  open,
  onClose,
  onSignOut,
  user,
  nickname,
  profilePhoto,
  portfolioUpdatedAt,
  positionCount,
}) {
  useEffect(() => {
    if (!open) return undefined
    const previousOverflow = document.body.style.overflow
    const onKeyDown = (event) => {
      if (event.key === 'Escape') onClose()
    }
    document.body.style.overflow = 'hidden'
    window.addEventListener('keydown', onKeyDown)
    return () => {
      document.body.style.overflow = previousOverflow
      window.removeEventListener('keydown', onKeyDown)
    }
  }, [open, onClose])

  if (!open) return null

  const displayName = nickname || user.displayName || 'Stock Stickies member'
  const initial = (displayName || user.email || '?').charAt(0).toUpperCase()

  return (
    <>
      <button className="scrim" type="button" aria-label="Close profile" onClick={onClose} />
      <aside className="profile-sheet" role="dialog" aria-modal="true" aria-labelledby="profile-title">
        <div className="sheet-handle" aria-hidden="true" />
        <header className="profile-sheet-header">
          <div>
            <p className="eyebrow">YOUR ACCOUNT</p>
            <h2 id="profile-title">Profile</h2>
          </div>
          <button className="icon-button" type="button" onClick={onClose} aria-label="Close profile" autoFocus>
            <Icon name="close" />
          </button>
        </header>

        <div className="profile-identity">
          {profilePhoto ? <img src={profilePhoto} alt="" /> : <span>{initial}</span>}
          <div>
            <strong>{displayName}</strong>
            <small>View-only mobile access</small>
          </div>
        </div>

        <dl className="profile-details">
          <div><dt>Email</dt><dd>{user.email || 'Not available'}</dd></div>
          <div><dt>Member since</dt><dd>{formatDate(user.metadata?.creationTime)}</dd></div>
          <div><dt>Last sign-in</dt><dd>{formatDateTime(user.metadata?.lastSignInTime)}</dd></div>
          <div><dt>Portfolio data</dt><dd>{portfolioUpdatedAt ? `Updated ${formatDateTime(portfolioUpdatedAt)}` : 'Update time unavailable'}</dd></div>
          <div><dt>Positions</dt><dd>{positionCount.toLocaleString()}</dd></div>
        </dl>

        <p className="persistence-note">
          This familiar device keeps you signed in securely until you choose Log out.
        </p>
        <button className="logout-button" type="button" onClick={onSignOut}>
          <Icon name="logout" />
          Log out
        </button>
      </aside>
    </>
  )
}

function Login() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const googleButtonRef = useRef(null)

  useEffect(() => {
    let cancelled = false

    const renderGoogleButton = () => {
      if (cancelled || !window.google?.accounts?.id || !googleButtonRef.current) return
      window.google.accounts.id.initialize({
        client_id: GOOGLE_CLIENT_ID,
        callback: async (response) => {
          setBusy(true)
          setError('')
          try {
            if (!auth || !response?.credential) throw new Error('Google did not return a sign-in credential.')
            await authPersistenceReady
            const credential = firebase.auth.GoogleAuthProvider.credential(response.credential)
            await auth.signInWithCredential(credential)
          } catch (reason) {
            setError(friendlyAuthError(reason))
          } finally {
            setBusy(false)
          }
        },
      })
      googleButtonRef.current.replaceChildren()
      window.google.accounts.id.renderButton(googleButtonRef.current, {
        type: 'standard',
        theme: 'filled_black',
        size: 'large',
        text: 'continue_with',
        shape: 'rectangular',
        logo_alignment: 'left',
        width: Math.min(350, googleButtonRef.current.clientWidth),
      })
    }

    const existingScript = document.querySelector('script[data-google-identity]')
    if (existingScript) {
      if (window.google?.accounts?.id) renderGoogleButton()
      else existingScript.addEventListener('load', renderGoogleButton, { once: true })
    } else {
      const script = document.createElement('script')
      script.src = 'https://accounts.google.com/gsi/client'
      script.async = true
      script.defer = true
      script.dataset.googleIdentity = 'true'
      script.addEventListener('load', renderGoogleButton, { once: true })
      script.addEventListener('error', () => {
        if (!cancelled) setError('Google sign-in could not load. You can still sign in with email.')
      }, { once: true })
      document.head.appendChild(script)
    }

    return () => {
      cancelled = true
    }
  }, [])

  const signIn = async (event) => {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      if (!auth) throw new Error('Firebase is not configured for this app.')
      await authPersistenceReady
      await auth.signInWithEmailAndPassword(email.trim().toLowerCase(), password)
    } catch (reason) {
      setError(friendlyAuthError(reason))
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="login-page">
      <section className="login-card">
        <StockStickiesLogo />
        <p className="eyebrow">MOBILE COMPANION</p>
        <p className="login-copy">Your portfolio, distilled for your phone. View-only and always dark.</p>
        <form onSubmit={signIn}>
          <label>
            Email
            <input
              type="email"
              inputMode="email"
              enterKeyHint="next"
              autoComplete="username"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck="false"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              required
            />
          </label>
          <label>
            Password
            <span className="password-field">
              <input
                type={showPassword ? 'text' : 'password'}
                enterKeyHint="go"
                autoComplete="current-password"
                autoCapitalize="none"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                required
              />
              <button type="button" onClick={() => setShowPassword((visible) => !visible)}>
                {showPassword ? 'Hide' : 'Show'}
              </button>
            </span>
          </label>
          {error && <p className="form-error" role="alert">{error}</p>}
          <button className="primary-button" type="submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
        </form>
        <div className="divider"><span>or</span></div>
        <div className={`google-signin-slot ${busy ? 'disabled' : ''}`} ref={googleButtonRef} aria-label="Continue with Google" />
        <p className="readonly-note"><span>●</span> This app can read your Stock Stickies data but never edits it.</p>
      </section>
    </main>
  )
}

export default function App() {
  const [user, setUser] = useState(null)
  const [authReady, setAuthReady] = useState(false)
  const [dataReady, setDataReady] = useState(false)
  const [dataError, setDataError] = useState('')
  const [notes, setNotes] = useState([])
  const [categories, setCategories] = useState([])
  const [colorLabels, setColorLabels] = useState({})
  const [cashSecuredPuts, setCashSecuredPuts] = useState([])
  const [watchList, setWatchList] = useState([])
  const [nickname, setNickname] = useState('')
  const [profilePhoto, setProfilePhoto] = useState('')
  const [profileOpen, setProfileOpen] = useState(false)
  const [portfolioUpdatedAt, setPortfolioUpdatedAt] = useState(null)
  const [finnhubKey, setFinnhubKey] = useState('')
  const [prices, setPrices] = useState({})
  const [lastUpdated, setLastUpdated] = useState(null)
  const [refreshing, setRefreshing] = useState(false)
  const [refreshMessage, setRefreshMessage] = useState('')
  const [chartExpanded, setChartExpanded] = useState(false)
  const [accountFilter, setAccountFilter] = useState('all')
  const [sortMode, setSortMode] = useState('size-desc')
  const [search, setSearch] = useState('')
  const [expandedId, setExpandedId] = useState(null)
  const [installEvent, setInstallEvent] = useState(null)

  useEffect(() => {
    const onInstall = (event) => {
      event.preventDefault()
      setInstallEvent(event)
    }
    window.addEventListener('beforeinstallprompt', onInstall)
    return () => window.removeEventListener('beforeinstallprompt', onInstall)
  }, [])

  useEffect(() => {
    if (!auth) {
      setAuthReady(true)
      return undefined
    }
    let unsubscribe = () => {}
    let cancelled = false
    authPersistenceReady.finally(() => {
      if (cancelled) return
      unsubscribe = auth.onAuthStateChanged((nextUser) => {
        setUser(nextUser)
        setAuthReady(true)
        if (!nextUser) {
          setDataReady(false)
          setNotes([])
          setPortfolioUpdatedAt(null)
          setProfileOpen(false)
          setChartExpanded(false)
        }
      })
    })
    return () => {
      cancelled = true
      unsubscribe()
    }
  }, [])

  useEffect(() => {
    if (!user || !db) return undefined
    const cacheKey = `stock-stickies-mobile-prices-${user.uid}`
    try {
      const cached = JSON.parse(localStorage.getItem(cacheKey) || '{}')
      if (cached.prices) setPrices(cached.prices)
      if (cached.timestamp) setLastUpdated(new Date(cached.timestamp))
    } catch {
      // Ignore a malformed device cache.
    }

    return db.collection('users').doc(user.uid).onSnapshot(async (snapshot) => {
      if (!snapshot.exists) {
        setDataError('No Stock Stickies portfolio was found for this account.')
        setDataReady(true)
        return
      }
      const data = snapshot.data() || {}
      const incomingNotes = Array.isArray(data.notes) ? data.notes : []
      setNotes(incomingNotes)
      setCategories(Array.isArray(data.categories) ? data.categories : [])
      setColorLabels(data.colorLabels || {})
      setCashSecuredPuts(Array.isArray(data.cashSecuredPuts) ? data.cashSecuredPuts : [])
      setWatchList(Array.isArray(data.watchList) ? data.watchList : [])
      setNickname(data.nickname || '')
      setProfilePhoto(data.profilePhoto || user.photoURL || '')
      setPortfolioUpdatedAt(
        typeof data.updatedAt?.toDate === 'function'
          ? data.updatedAt.toDate()
          : (data.updatedAt ? new Date(data.updatedAt) : null),
      )
      setFinnhubKey(await decryptApiKey(data.finnhubApiKey, user.uid))
      setPrices((current) => {
        const seeded = { ...current }
        incomingNotes.forEach((note) => {
          const ticker = normalizeTicker(note.title)
          const sourcePrice = plaidPrice(note)
          if (ticker === 'USD') seeded[ticker] = 1
          else if (ticker && sourcePrice > 0 && (!seeded[ticker] || isCrypto(note))) seeded[ticker] = sourcePrice
        })
        return seeded
      })
      setDataError('')
      setDataReady(true)
    }, (error) => {
      setDataError(error?.message || 'Unable to load the portfolio.')
      setDataReady(true)
    })
  }, [user])

  const portfolioNotes = useMemo(
    () => notes.filter((note) => normalizeTicker(note.title) && Number(note.shares) > 0),
    [notes],
  )

  const allPositions = useMemo(() => {
    const raw = portfolioNotes.map((note) => {
      const ticker = normalizeTicker(note.title)
      const price = ticker === 'USD' ? 1 : Number(prices[ticker] || plaidPrice(note) || 0)
      const shares = Number(note.shares) || 0
      const category = colorLabels[note.color] || 'Unclassified'
      return {
        id: note.id,
        ticker,
        shares,
        price,
        value: shares * price,
        account: getAccount(note),
        category,
        note: String(note.text || '').trim(),
        isCash: category.trim().toLowerCase() === 'cash' || ticker === 'USD' || ticker === 'SGOV',
      }
    })
    const total = raw.reduce((sum, position) => sum + position.value, 0)
    return raw.map((position) => ({
      ...position,
      percentage: total > 0 ? (position.value / total) * 100 : 0,
    }))
  }, [portfolioNotes, prices, colorLabels])

  const accountTotals = useMemo(() => {
    const totals = {}
    allPositions.forEach((position) => {
      if (!totals[position.account]) totals[position.account] = { value: 0, count: 0 }
      totals[position.account].value += position.value
      totals[position.account].count += 1
    })
    return totals
  }, [allPositions])

  const filteredPositions = useMemo(() => {
    const scoped = accountFilter === 'all'
      ? allPositions
      : allPositions.filter((position) => position.account === accountFilter)
    const scopedTotal = scoped.reduce((sum, position) => sum + position.value, 0)
    return scoped.map((position) => ({
      ...position,
      percentage: scopedTotal > 0 ? (position.value / scopedTotal) * 100 : 0,
    }))
  }, [allPositions, accountFilter])

  const sortedPositions = useMemo(() => {
    const query = search.trim().toUpperCase()
    const result = filteredPositions.filter((position) => !query || position.ticker.includes(query) || position.category.toUpperCase().includes(query))
    return result.sort((a, b) => {
      if (sortMode === 'name-asc') return a.ticker.localeCompare(b.ticker)
      if (sortMode === 'name-desc') return b.ticker.localeCompare(a.ticker)
      if (sortMode === 'size-asc') return a.value - b.value || a.ticker.localeCompare(b.ticker)
      if (sortMode === 'shares-desc') return b.shares - a.shares || a.ticker.localeCompare(b.ticker)
      if (sortMode === 'price-desc') return b.price - a.price || a.ticker.localeCompare(b.ticker)
      return b.value - a.value || a.ticker.localeCompare(b.ticker)
    })
  }, [filteredPositions, search, sortMode])

  const total = filteredPositions.reduce((sum, position) => sum + position.value, 0)
  const cashValue = filteredPositions.filter((position) => position.isCash).reduce((sum, position) => sum + position.value, 0)
  const missingPrices = filteredPositions.filter((position) => position.price <= 0).length
  const putObligationByAccount = useMemo(() => {
    const totals = {}
    cashSecuredPuts.forEach((put) => {
      const account = getPutAccount(put)
      totals[account] = (totals[account] || 0) + (Number(put.strike) || 0) * (Number(put.qty) || 0) * 100
    })
    return totals
  }, [cashSecuredPuts])
  const totalPutObligation = Object.values(putObligationByAccount).reduce((sum, value) => sum + value, 0)

  const askKPortfolio = useMemo(() => {
    const grandTotal = allPositions.reduce((sum, position) => sum + position.value, 0)
    const positionIds = new Set(allPositions.map((position) => position.id))
    return {
      asOf: new Date().toISOString(),
      nickname: nickname || null,
      totals: {
        longMarketValue: Number(grandTotal.toFixed(2)),
        cspObligation: Number(totalPutObligation.toFixed(2)),
        longPlusCspExposure: Number((grandTotal + totalPutObligation).toFixed(2)),
        positionCount: allPositions.length,
        cspCount: cashSecuredPuts.length,
        missingPrices: allPositions.filter((position) => position.price <= 0).length,
      },
      accounts: [
        ...ACCOUNTS.map((account) => ({
          id: account.id,
          label: account.label,
          strategy: account.strategy,
          marketValue: Number((accountTotals[account.id]?.value || 0).toFixed(2)),
          positionCount: accountTotals[account.id]?.count || 0,
          percentOfTotal: grandTotal > 0 ? Number((((accountTotals[account.id]?.value || 0) / grandTotal) * 100).toFixed(2)) : 0,
          cspObligation: Number((putObligationByAccount[account.id] || 0).toFixed(2)),
        })),
        ...(accountTotals[UNASSIGNED] ? [{
          id: UNASSIGNED,
          label: 'Unassigned',
          strategy: 'Positions not yet assigned to an account.',
          marketValue: Number(accountTotals[UNASSIGNED].value.toFixed(2)),
          positionCount: accountTotals[UNASSIGNED].count,
          percentOfTotal: grandTotal > 0 ? Number(((accountTotals[UNASSIGNED].value / grandTotal) * 100).toFixed(2)) : 0,
        }] : []),
      ],
      positions: allPositions.map((position) => ({
        ticker: position.ticker,
        shares: position.shares,
        price: Number(position.price.toFixed(4)),
        value: Number(position.value.toFixed(2)),
        percentOfPortfolio: Number(position.percentage.toFixed(2)),
        account: position.account,
        accountLabel: getAccountLabel(position.account),
        percentOfAccount: accountTotals[position.account]?.value > 0
          ? Number(((position.value / accountTotals[position.account].value) * 100).toFixed(2))
          : 0,
        category: position.category,
        note: position.note.slice(0, 1500),
      })),
      researchNotes: notes
        .filter((note) => note.title && note.text && !positionIds.has(note.id))
        .slice(0, 50)
        .map((note) => ({ ticker: normalizeTicker(note.title), category: colorLabels[note.color] || 'Unclassified', note: String(note.text).slice(0, 1500) })),
      cashSecuredPuts: cashSecuredPuts.map((put) => ({
        ticker: put.ticker,
        strike: Number(put.strike) || 0,
        qty: Number(put.qty) || 0,
        expiry: put.expiry || null,
        obligation: (Number(put.strike) || 0) * (Number(put.qty) || 0) * 100,
        account: getPutAccount(put),
        accountLabel: getAccountLabel(getPutAccount(put)),
      })),
      watchList: watchList.slice(0, 100),
      categories: categories.map((color) => ({ color, label: colorLabels[color] || 'Category' })),
    }
  }, [allPositions, accountTotals, cashSecuredPuts, categories, colorLabels, nickname, notes, putObligationByAccount, totalPutObligation, watchList])

  const refreshPrices = async () => {
    if (!portfolioNotes.length || refreshing) return
    const needsFinnhub = portfolioNotes.some((note) => normalizeTicker(note.title) !== 'USD' && !isCrypto(note))
    if (needsFinnhub && !finnhubKey) {
      setRefreshMessage('Add a Finnhub key in the desktop app, then try again.')
      return
    }
    setRefreshing(true)
    setRefreshMessage('')
    const nextPrices = { ...prices }
    let failures = 0
    for (const note of portfolioNotes) {
      const ticker = normalizeTicker(note.title)
      try {
        if (ticker === 'USD') {
          nextPrices[ticker] = 1
          continue
        }
        if (isCrypto(note) && plaidPrice(note) > 0) {
          nextPrices[ticker] = plaidPrice(note)
          continue
        }
        const response = await fetch(`https://finnhub.io/api/v1/quote?symbol=${encodeURIComponent(ticker)}&token=${encodeURIComponent(finnhubKey)}`)
        if (!response.ok) throw new Error('Quote request failed')
        const quote = await response.json()
        const currentPrice = Number(quote?.c)
        if (currentPrice > 0) nextPrices[ticker] = currentPrice
        else failures += 1
      } catch {
        failures += 1
      }
    }
    const timestamp = Date.now()
    setPrices(nextPrices)
    setLastUpdated(new Date(timestamp))
    setRefreshing(false)
    setRefreshMessage(failures ? `${failures} quote${failures === 1 ? '' : 's'} could not be updated.` : 'All quotes are current.')
    localStorage.setItem(`stock-stickies-mobile-prices-${user.uid}`, JSON.stringify({ prices: nextPrices, timestamp }))
  }

  const install = async () => {
    if (!installEvent) return
    await installEvent.prompt()
    setInstallEvent(null)
  }

  const signOut = async () => {
    setProfileOpen(false)
    await auth.signOut()
  }

  if (!authReady) return <div className="splash"><StockStickiesLogo /><p>Opening your portfolio…</p></div>
  if (!user) return <Login />
  if (!dataReady) return <div className="splash"><div className="loader" /><p>Loading your portfolio…</p></div>

  const presentAccounts = [
    ...ACCOUNT_IDS.filter((id) => accountTotals[id]),
    ...(accountTotals[UNASSIGNED] ? [UNASSIGNED] : []),
  ]

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <StockStickiesLogo compact />
          <small>Mobile Portfolio</small>
        </div>
        <div className="top-actions">
          {installEvent && <button className="icon-button" type="button" onClick={install} aria-label="Install app"><Icon name="install" /></button>}
          <button className="profile-button" type="button" onClick={() => setProfileOpen(true)} aria-label="Open profile">
            {profilePhoto ? <img src={profilePhoto} alt="" /> : <span>{(nickname || user.email || '?').charAt(0).toUpperCase()}</span>}
            <Icon name="chevron" size={15} />
          </button>
        </div>
      </header>

      <main className="dashboard">
        <section className="hero">
          <div className="hero-topline">
            <div>
              <p className="eyebrow">{accountFilter === 'all' ? 'ALL ACCOUNTS' : getAccountLabel(accountFilter).toUpperCase()}</p>
              <h1>{money(total)}</h1>
            </div>
            <button className="refresh-button" type="button" onClick={refreshPrices} disabled={refreshing}>
              <Icon name="refresh" />
              <span>{refreshing ? 'Updating…' : 'Update'}</span>
            </button>
          </div>
          <div className="status-line">
            <span className={missingPrices ? 'status-dot warning' : 'status-dot'} />
            <span className="status-copy">
              <strong>{portfolioUpdatedAt ? `Portfolio updated ${formatDateTime(portfolioUpdatedAt)}` : 'Portfolio update time unavailable'}</strong>
              <small>{lastUpdated ? `Prices updated ${formatDateTime(lastUpdated)}` : 'Tap Update to fetch current quotes'}</small>
            </span>
          </div>
          {refreshMessage && <p className="refresh-message" role="status">{refreshMessage}</p>}
        </section>

        {dataError ? <div className="error-card">{dataError}</div> : (
          <>
            <nav className="account-scroller" aria-label="Filter by account">
              <button type="button" className={accountFilter === 'all' ? 'active' : ''} onClick={() => setAccountFilter('all')}>
                <span>All accounts</span><strong>{money(allPositions.reduce((sum, position) => sum + position.value, 0))}</strong>
              </button>
              {presentAccounts.map((id) => (
                <button type="button" key={id} className={accountFilter === id ? 'active' : ''} onClick={() => setAccountFilter(id)}>
                  <span>{ACCOUNTS.find((account) => account.id === id)?.short || 'Unassigned'}</span>
                  <strong>{money(accountTotals[id]?.value)}</strong>
                </button>
              ))}
            </nav>

            <section className={`chart-card ${chartExpanded ? 'expanded' : 'minimized'}`}>
              <div className="chart-card-header">
                <div>
                  <span>Portfolio allocation</span>
                  <strong>{filteredPositions.length} positions · {money(total)}</strong>
                </div>
                <button
                  type="button"
                  onClick={() => setChartExpanded((expanded) => !expanded)}
                  aria-expanded={chartExpanded}
                  aria-controls="mobile-allocation-chart"
                >
                  {chartExpanded ? 'Minimize' : 'Maximize'}
                  <Icon name="chevron" size={16} />
                </button>
              </div>
              {chartExpanded && (
                <div id="mobile-allocation-chart">
                  {filteredPositions.length ? <PortfolioDonut positions={filteredPositions} total={total} cashValue={cashValue} /> : <div className="empty-chart">No positions in this account.</div>}
                  <div className="chart-stats">
                    <div><span>Positions</span><strong>{filteredPositions.length}</strong></div>
                    <div><span>Cash</span><strong>{money(cashValue)}</strong></div>
                    <div><span>CSP obligation</span><strong>{money(accountFilter === 'all' ? totalPutObligation : putObligationByAccount[accountFilter])}</strong></div>
                  </div>
                </div>
              )}
            </section>

            <section className="positions-section">
              <div className="section-heading">
                <div><p className="eyebrow">HOLDINGS</p><h2>Positions</h2></div>
                <span>{sortedPositions.length} shown</span>
              </div>
              <div className="position-tools">
                <label className="search-field"><Icon name="search" size={18} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Find a ticker" aria-label="Search positions" /></label>
                <label className="sort-field">
                  <span className="sr-only">Sort positions</span>
                  <select value={sortMode} onChange={(event) => setSortMode(event.target.value)}>
                    <option value="size-desc">Largest</option>
                    <option value="size-asc">Smallest</option>
                    <option value="name-asc">Name A–Z</option>
                    <option value="name-desc">Name Z–A</option>
                    <option value="shares-desc">Most shares</option>
                    <option value="price-desc">Price</option>
                  </select>
                  <Icon name="chevron" size={16} />
                </label>
              </div>

              <div className="position-list">
                {sortedPositions.map((position, index) => (
                  <article className={`position-row ${expandedId === position.id ? 'expanded' : ''}`} key={position.id}>
                    <button type="button" onClick={() => setExpandedId(expandedId === position.id ? null : position.id)} aria-expanded={expandedId === position.id}>
                      <div className="rank">{index + 1}</div>
                      <div className="ticker-block">
                        <strong>{position.ticker}</strong>
                        <span>{position.category} · {getAccountLabel(position.account)}</span>
                      </div>
                      <div className="value-block">
                        <strong>{money(position.value)}</strong>
                        <span>{position.percentage.toFixed(2)}%</span>
                      </div>
                      <Icon name="chevron" size={16} />
                    </button>
                    {expandedId === position.id && (
                      <div className="position-detail">
                        <div><span>Shares</span><strong>{number(position.shares, 6)}</strong></div>
                        <div><span>Price</span><strong>{position.price ? money(position.price, 2) : 'Unavailable'}</strong></div>
                        <div><span>Market value</span><strong>{money(position.value, 2)}</strong></div>
                        {position.note && <p>{position.note}</p>}
                        <small>Read-only · Edit this position in the desktop app.</small>
                      </div>
                    )}
                  </article>
                ))}
                {!sortedPositions.length && <div className="empty-list">No positions match this view.</div>}
              </div>
            </section>
          </>
        )}
      </main>

      <ProfileSheet
        open={profileOpen}
        onClose={() => setProfileOpen(false)}
        onSignOut={signOut}
        user={user}
        nickname={nickname}
        profilePhoto={profilePhoto}
        portfolioUpdatedAt={portfolioUpdatedAt}
        positionCount={allPositions.length}
      />
      <AskK portfolio={askKPortfolio} />
    </div>
  )
}
