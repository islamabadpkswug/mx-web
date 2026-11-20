import re
import socket
import time
PORT25_CONTROLS = ('gmail-smtp-in.l.google.com', 'mx1.hostinger.com', 'mail.protonmail.ch')
_P25 = {'at': None, 'shut': False}

def port25_shut(ttl=600):
    now = time.monotonic()
    if _P25['at'] is not None and now - _P25['at'] < ttl:
        return _P25['shut']
    shut = True
    for h in PORT25_CONTROLS:
        try:
            socket.create_connection((h, 25), 6).close()
            shut = False
            break
        except OSError:
            continue
    _P25.update(at=now, shut=shut)
    return shut
DEAD_RE = re.compile("\\b5\\.1\\.(0|1|10)\\b|\\b5\\.2\\.1\\b|AS\\(201806281\\)|does ?n[o']t exist|no such user|user unknown|unknown user|recipient not found|address rejected|invalid recipient|mailbox (is )?(unavailable|disabled|not found)|account (is )?(disabled|inactive)|undeliverable address|not a valid mailbox|no mailbox here", re.I)
BLOCKED_RE = re.compile('\\b5\\.7\\.\\d+\\b|spamhaus|blocked|blacklist|block ?list|policy|reputation|not allowed|denied by|rbl|dnsbl|client host|helo|reverse dns|ptr|\\bspf\\b|temporar|try again|too many|rate|greylist|\\bsender\\b|relay', re.I)

def _dead_text(code, text):
    return 500 <= code < 600 and bool(DEAD_RE.search(text)) and (not BLOCKED_RE.search(text))

def smtp_probe(addr, timeout=20):
    try:
        return _probe(addr, timeout)
    except Exception as e:
        return ('unknown', f'probe error {type(e).__name__}: {str(e)[:120]}')

def _probe(addr, timeout):
    import secrets
    import smtplib
    from emailaudit import resolver as R
    addr = addr.strip().lower()
    dom = addr.rsplit('@', 1)[-1]
    st, ans = R.query(dom, 'MX')
    if st == R.NXDOMAIN:
        return ('dead', f'{dom} does not exist in DNS (NXDOMAIN)')
    exch = [(a.preference, str(a.exchange).rstrip('.')) for a in ans or []]
    if exch and all((h == '' for _, h in exch)):
        return ('dead', f'{dom} publishes a null MX (RFC 7505): it accepts no mail')
    hosts = [h for _, h in sorted(exch) if h]
    if not hosts:
        if st == R.NOANSWER:
            sa, aa = R.query(dom, 'A')
            if sa == R.NXDOMAIN or (sa == R.NOANSWER and (not aa)):
                return ('dead', f'{dom} has no MX and no A record: mail cannot be delivered')
            if sa != R.OK:
                return ('unknown', f'A lookup for {dom}: {sa}')
            hosts = [dom]
        else:
            return ('unknown', f'MX lookup for {dom}: {st}')
    if port25_shut():
        ra = remote_answer(addr)
        if ra:
            return ra
        return ('unknown', 'port 25 shut on this connection, server not asked')
    helo = 'verify.citant.ai'
    last = ''
    for host in hosts[:2]:
        try:
            s = smtplib.SMTP(host, 25, timeout=timeout, local_hostname=helo)
            try:
                s.ehlo()
                code, msg = s.mail('')
                if code != 250:
                    last = f"{host} MAIL FROM {code} {msg.decode(errors='replace')[:120]}"
                    continue
                c1, m1 = s.rcpt(addr)
                c2, m2 = s.rcpt(f'no-such-{secrets.token_hex(5)}@{dom}')
                try:
                    s.rset()
                    s.quit()
                except smtplib.SMTPException:
                    pass
            finally:
                try:
                    s.close()
                except Exception:
                    pass
            t1, t2 = (m1.decode(errors='replace'), m2.decode(errors='replace'))
            note = ''
            if c1 in (250, 251) and 400 <= c2 < 500:
                first = f'{c2} {t2[:40]}'
                for wait in (3, 10, 45):
                    if _RETRY_BUDGET['s'] < wait:
                        break
                    _RETRY_BUDGET['s'] -= wait
                    time.sleep(wait)
                    c2b, t2b = _rcpt_once(host, helo, f'no-such-{secrets.token_hex(5)}@{dom}', timeout)
                    if c2b is None:
                        continue
                    c2, t2 = (c2b, t2b)
                    note = f' [control asked again on a fresh session; first try {first}]'
                    if not 400 <= c2 < 500:
                        break
            line = f'{host}: target {c1} {t1[:140]} | control {c2} {t2[:80]}{note}'
            if c1 in (250, 251):
                if c2 in (250, 251):
                    return ('catch_all', line)
                return ('exists' if _dead_text(c2, t2) else 'unknown', line)
            if _dead_text(c1, t1):
                return ('dead', line)
            return ('unknown', line)
        except (OSError, smtplib.SMTPException) as e:
            last = f'{host}: {type(e).__name__} {str(e)[:120]}'
    return ('unknown', last or 'no MX host answered')
_RETRY_BUDGET = {'s': 300}

def _rcpt_once(host, helo, rcpt, timeout):
    import smtplib
    try:
        s = smtplib.SMTP(host, 25, timeout=timeout, local_hostname=helo)
        try:
            s.ehlo()
            code, msg = s.mail('')
            if code != 250:
                return (None, f'MAIL FROM {code}')
            c, m = s.rcpt(rcpt)
            try:
                s.rset()
                s.quit()
            except smtplib.SMTPException:
                pass
            return (c, m.decode(errors='replace'))
        finally:
            try:
                s.close()
            except Exception:
                pass
    except (OSError, smtplib.SMTPException) as e:
        return (None, f'{type(e).__name__} {str(e)[:80]}')
import json as _json
import os as _os
from pathlib import Path as _Path

def _prf(k, msg):
    import hashlib
    import hmac
    return hmac.new(k, msg, hashlib.sha256).digest()

def seal(key_hex, data):
    import base64
    import secrets as _s
    k = bytes.fromhex(key_hex.strip())
    ke, km, nonce = (_prf(k, b'enc'), _prf(k, b'mac'), _s.token_bytes(16))
    data = data.encode() if isinstance(data, str) else data
    ks = b''.join((_prf(ke, nonce + i.to_bytes(8, 'big')) for i in range(len(data) // 32 + 1)))
    ct = bytes((a ^ b for a, b in zip(data, ks)))
    return base64.b64encode(nonce + ct + _prf(km, nonce + ct)[:16]).decode()

def unseal(key_hex, text):
    import base64
    import hmac
    k = bytes.fromhex(key_hex.strip())
    ke, km = (_prf(k, b'enc'), _prf(k, b'mac'))
    raw = base64.b64decode(text)
    nonce, ct, tag = (raw[:16], raw[16:-16], raw[-16:])
    if len(raw) < 32 or not hmac.compare_digest(tag, _prf(km, nonce + ct)[:16]):
        raise ValueError('sealed text failed its check (wrong key or changed)')
    ks = b''.join((_prf(ke, nonce + i.to_bytes(8, 'big')) for i in range(len(ct) // 32 + 1)))
    return bytes((a ^ b for a, b in zip(ct, ks))).decode()

def remote_answer(*a, **k):
    return None
