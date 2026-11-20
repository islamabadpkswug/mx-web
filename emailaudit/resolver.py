import dns.resolver
import dns.query
import dns.message
import dns.rdatatype
import dns.exception
OK, NXDOMAIN, NOANSWER, TIMEOUT, SERVFAIL, ERROR = ('OK', 'NXDOMAIN', 'NOANSWER', 'TIMEOUT', 'SERVFAIL', 'ERROR')
_resolver = None

def get_resolver():
    global _resolver
    if _resolver is None:
        r = dns.resolver.Resolver()
        r.timeout = 5
        r.lifetime = 12
        if not r.nameservers:
            r.nameservers = ['1.1.1.1', '8.8.8.8']
        _resolver = r
    return _resolver

def resolver_ips():
    return list(get_resolver().nameservers)
FALLBACK_NAMESERVERS = ['1.1.1.1', '8.8.8.8', '9.9.9.9']
_fallback = None

def _fallback_resolver():
    global _fallback
    if _fallback is None:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = FALLBACK_NAMESERVERS
        r.timeout = 5
        r.lifetime = 12
        _fallback = r
    return _fallback

def _resolve_once(resolver, name, rtype):
    try:
        ans = resolver.resolve(name, rtype)
        return (OK, list(ans))
    except dns.resolver.NXDOMAIN:
        return (NXDOMAIN, [])
    except dns.resolver.NoAnswer:
        return (NOANSWER, [])
    except dns.resolver.NoNameservers:
        return (SERVFAIL, [])
    except dns.exception.Timeout:
        return (TIMEOUT, [])
    except Exception as e:
        return (ERROR, [str(e)])
_doh_only = False
DOH_URLS = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/dns-query']
_DOH_FLAG = __import__('pathlib').Path(__file__).resolve().parent.parent / 'logs' / 'doh-only.flag'
_DOH_FLAG_SECONDS = 3600

def _doh_flag_fresh():
    import time
    try:
        return time.time() - _DOH_FLAG.stat().st_mtime < _DOH_FLAG_SECONDS
    except OSError:
        return False

def _set_doh_only():
    global _doh_only
    _doh_only = True
    try:
        _DOH_FLAG.parent.mkdir(parents=True, exist_ok=True)
        _DOH_FLAG.write_text('plain port-53 DNS timed out; DNS over HTTPS answered\n', encoding='utf-8')
    except OSError:
        pass

def _resolve_doh(name, rtype):
    import requests
    import dns.rcode
    for url in DOH_URLS:
        try:
            q = dns.message.make_query(name, rtype)
            r = requests.post(url, data=q.to_wire(), timeout=10, headers={'content-type': 'application/dns-message', 'accept': 'application/dns-message'})
            r.raise_for_status()
            m = dns.message.from_wire(r.content)
        except Exception:
            continue
        if m.rcode() == dns.rcode.NXDOMAIN:
            return (NXDOMAIN, [])
        if m.rcode() != dns.rcode.NOERROR:
            return (SERVFAIL, [])
        want = dns.rdatatype.from_text(rtype) if isinstance(rtype, str) else rtype
        ans = [rd for rr in m.answer if rr.rdtype == want for rd in rr]
        return (OK, ans) if ans else (NOANSWER, [])
    return (TIMEOUT, [])

def query(name, rtype):
    if _doh_only or _doh_flag_fresh():
        st0, ans0 = _resolve_doh(name, rtype)
        if st0 not in (TIMEOUT, SERVFAIL, ERROR) or _doh_only:
            return (st0, ans0)
    st, ans = _resolve_once(get_resolver(), name, rtype)
    if st in (TIMEOUT, SERVFAIL, ERROR):
        st2, ans2 = _resolve_once(_fallback_resolver(), name, rtype)
        if st2 not in (TIMEOUT, SERVFAIL, ERROR):
            return (st2, ans2)
        st3, ans3 = _resolve_doh(name, rtype)
        if st3 not in (TIMEOUT, SERVFAIL, ERROR):
            if st == TIMEOUT and st2 == TIMEOUT:
                _set_doh_only()
            return (st3, ans3)
    return (st, ans)

def preflight():
    st, _ = _resolve_once(get_resolver(), 'a.root-servers.net', 'A')
    if st == OK:
        return (True, f'system resolver {resolver_ips()} answering')
    st2, _ = _resolve_once(_fallback_resolver(), 'a.root-servers.net', 'A')
    if st2 == OK:
        return (True, f'OK via fallback {FALLBACK_NAMESERVERS} (system resolver {resolver_ips()} not answering: {st})')
    st3, _ = _resolve_doh('a.root-servers.net', 'A')
    if st3 == OK:
        _set_doh_only()
        return (True, f'OK via DNS over HTTPS {DOH_URLS[0]} (port 53 not answering: system resolver {resolver_ips()} {st}, fallback {FALLBACK_NAMESERVERS} {st2}; usual cause: VPN tunnel up)')
    return (False, f'no DNS at all (system {st}, fallback {st2}, https {st3}); check VPN / network')

def txt_strings(name):
    status, rds = query(name, 'TXT')
    if status != OK:
        return (status, [])
    out = []
    for rd in rds:
        out.append(b''.join(rd.strings).decode('utf-8', 'replace'))
    return (OK, out)

def a_records(name):
    ips = []
    for rt in ('A', 'AAAA'):
        st, rds = query(name, rt)
        if st == OK:
            ips += [rd.address for rd in rds]
    return ips

def query_authoritative(name, rtype, zone):
    if _doh_only:
        return (TIMEOUT, ['plain DNS blocked on this network (VPN?): authoritative query impossible'])
    st, ns_rds = query(zone, 'NS')
    if st != OK:
        return (ERROR, [f'no NS for {zone}: {st}'])
    last = ERROR
    for ns in ns_rds:
        for ip in a_records(str(ns.target)):
            if ':' in ip:
                continue
            try:
                q = dns.message.make_query(name, rtype)
                resp = dns.query.udp(q, ip, timeout=5)
                rcode = resp.rcode()
                if rcode == dns.rcode.NXDOMAIN:
                    return (NXDOMAIN, [])
                if rcode != dns.rcode.NOERROR:
                    last = SERVFAIL
                    continue
                rrs = [rr for rrset in resp.answer for rr in rrset if rrset.rdtype == dns.rdatatype.from_text(rtype)]
                if not rrs:
                    return (NOANSWER, [])
                return (OK, rrs)
            except dns.exception.Timeout:
                last = TIMEOUT
            except Exception:
                last = ERROR
    return (last, [])
