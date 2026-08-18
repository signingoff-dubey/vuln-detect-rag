const SAFE_PROTOCOLS = ['http:', 'https:', 'ftp:']

export function sanitizeUrl(url) {
  if (!url || typeof url !== 'string') return null
  try {
    const parsed = new URL(url)
    if (!SAFE_PROTOCOLS.includes(parsed.protocol)) return null
    return parsed.href
  } catch {
    if (url.startsWith('//') || url.startsWith('/')) return url
    return null
  }
}
