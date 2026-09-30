import { useRef, useState } from 'react'
import { FileSearch, Link2, Upload, ShieldAlert, ShieldCheck, ShieldQuestion, Copy, Check } from 'lucide-react'
import { sanitizeFile, sanitizeLink } from '../api/client'
import { Badge, Button, Callout, Card, CardHeader, Input, PageHeader, Segmented, cx } from '../components/ui'

const MODES = [
  { value: 'file', label: 'File', icon: FileSearch },
  { value: 'link', label: 'Link', icon: Link2 },
]

const VERDICT = {
  clean: { tone: 'ok', icon: ShieldCheck, label: 'No risky indicators' },
  suspicious: { tone: 'warn', icon: ShieldQuestion, label: 'Suspicious' },
  dangerous: { tone: 'crit', icon: ShieldAlert, label: 'Dangerous' },
}
const SEVERITY_TONE = { critical: 'crit', high: 'high', medium: 'med', low: 'low', info: 'neutral' }

function formatBytes(n) {
  if (n < 1024) return `${n} B`
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1048576).toFixed(1)} MB`
}

function CopyValue({ value, label }) {
  const [done, setDone] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value)
      setDone(true)
      setTimeout(() => setDone(false), 1500)
    } catch {
      // clipboard unavailable; the value stays selectable on screen
    }
  }
  return (
    <div className="flex items-center gap-2 min-w-0">
      <span className="text-xs text-ink-subtle w-14 flex-shrink-0">{label}</span>
      <code className="font-mono text-xs text-ink break-all flex-1 min-w-0">{value}</code>
      <button type="button" onClick={copy} aria-label={`Copy ${label}`} className="text-ink-subtle hover:text-ink flex-shrink-0">
        {done ? <Check className="w-3.5 h-3.5" aria-hidden="true" /> : <Copy className="w-3.5 h-3.5" aria-hidden="true" />}
      </button>
    </div>
  )
}

function Verdict({ result }) {
  const v = VERDICT[result.verdict]
  return (
    <Callout tone={v.tone} icon={v.icon} title={`${v.label} (risk ${result.score}/100)`} role="status">
      Static checks only. Nothing was opened, run or rendered.
    </Callout>
  )
}

function Findings({ findings }) {
  return (
    <ul className="divide-y divide-line">
      {findings.map((f, i) => (
        <li key={i} className="px-5 py-3 flex items-start gap-3">
          <Badge tone={SEVERITY_TONE[f.severity]} className="mt-0.5 capitalize flex-shrink-0">{f.severity}</Badge>
          <div className="min-w-0">
            <p className="text-sm text-ink">{f.title}</p>
            <p className="text-[13px] text-ink-muted break-words">{f.detail}</p>
          </div>
        </li>
      ))}
    </ul>
  )
}

function FilePanel({ onResult, setError, busy, setBusy }) {
  const inputRef = useRef(null)
  const [drag, setDrag] = useState(false)

  const run = async (file) => {
    if (!file) return
    setError(null)
    setBusy(true)
    try {
      const { data } = await sanitizeFile(file)
      onResult(data)
    } catch (err) {
      onResult(null)
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div
      onDragOver={(e) => { e.preventDefault(); setDrag(true) }}
      onDragLeave={() => setDrag(false)}
      onDrop={(e) => { e.preventDefault(); setDrag(false); run(e.dataTransfer.files?.[0]) }}
      className={cx(
        'rounded-card border-2 border-dashed px-6 py-10 text-center transition-colors duration-150',
        drag ? 'border-accent bg-accent-soft' : 'border-line bg-sunken'
      )}
    >
      <Upload className="w-6 h-6 text-ink-subtle mx-auto mb-2" aria-hidden="true" />
      <p className="text-sm text-ink">Drop a file here to inspect it</p>
      <p className="text-[13px] text-ink-muted mt-1">Up to 25 MB. The file is analysed as bytes and never opened.</p>
      <input ref={inputRef} type="file" className="sr-only" aria-label="Choose a file to inspect" onChange={(e) => { run(e.target.files?.[0]); e.target.value = '' }} />
      <Button className="mt-4" variant="primary" icon={Upload} loading={busy} onClick={() => inputRef.current?.click()}>
        {busy ? 'Inspecting' : 'Choose file'}
      </Button>
    </div>
  )
}

function LinkPanel({ onResult, setError, busy, setBusy }) {
  const [url, setUrl] = useState('')
  const [trace, setTrace] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    if (!url.trim()) return
    setError(null)
    setBusy(true)
    try {
      const { data } = await sanitizeLink(url.trim(), trace)
      onResult(data)
    } catch (err) {
      onResult(null)
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} className="space-y-3">
      <div className="flex gap-2">
        <Input
          icon={Link2}
          aria-label="Link to inspect"
          className="flex-1 min-w-0"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="Paste a suspicious link"
          autoComplete="off"
          spellCheck={false}
        />
        <Button type="submit" variant="primary" loading={busy}>{busy ? 'Checking' : 'Check link'}</Button>
      </div>
      <label className="flex items-start gap-2 text-[13px] text-ink-muted cursor-pointer">
        <input type="checkbox" checked={trace} onChange={(e) => setTrace(e.target.checked)} className="mt-0.5" />
        <span>
          Trace redirects. The server sends a header-only request to each hop to reveal the final destination.
          Internal and private addresses are never contacted.
        </span>
      </label>
    </form>
  )
}

export default function Sanitize() {
  const [mode, setMode] = useState('file')
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  const switchMode = (m) => { setMode(m); setResult(null); setError(null) }
  const panel = { onResult: setResult, setError, busy, setBusy }

  return (
    <div>
      <PageHeader
        title="File and link check"
        description="Inspect an untrusted file or link for hidden risks before you open it."
      />

      <Segmented label="What to check" value={mode} onChange={switchMode} options={MODES} className="mb-4" />

      <Card className="p-5 mb-6">
        {mode === 'file' ? <FilePanel {...panel} /> : <LinkPanel {...panel} />}
      </Card>

      {error && <Callout tone="crit" icon={ShieldAlert} title="Could not check" role="alert" className="mb-6">{error}</Callout>}

      {result && (
        <div className="space-y-4" aria-live="polite">
          <Verdict result={result} />

          <Card>
            <CardHeader title={mode === 'file' ? 'File details' : 'Safe versions of this link'} />
            <div className="px-5 pb-4 space-y-2">
              {mode === 'file' ? (
                <>
                  <p className="text-sm text-ink break-all">
                    {result.filename} <span className="text-ink-subtle">· {formatBytes(result.size)} · detected as {result.detected_type}</span>
                  </p>
                  <CopyValue label="SHA-256" value={result.hashes.sha256} />
                  <CopyValue label="SHA-1" value={result.hashes.sha1} />
                  <CopyValue label="MD5" value={result.hashes.md5} />
                </>
              ) : (
                <>
                  <CopyValue label="Defanged" value={result.defanged} />
                  {result.clean_url && <CopyValue label="Cleaned" value={result.clean_url} />}
                  {result.redirects?.length > 0 && (
                    <ol className="pt-2 space-y-1 text-xs">
                      {result.redirects.map((h, i) => (
                        <li key={i} className="font-mono break-all text-ink-muted">
                          {i + 1}. {h.status ?? '—'} {h.url}{h.note ? ` (${h.note})` : ''}
                        </li>
                      ))}
                    </ol>
                  )}
                </>
              )}
            </div>
          </Card>

          <Card className="overflow-hidden">
            <CardHeader title="Findings" description="Ordered as detected. The score adds up severity across findings." />
            <Findings findings={result.findings} />
          </Card>
        </div>
      )}
    </div>
  )
}
