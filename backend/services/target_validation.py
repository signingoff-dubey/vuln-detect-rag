import ipaddress
import re
import socket

from fastapi import HTTPException

_LABEL = r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
_HOSTNAME = re.compile(rf"^(?:{_LABEL}\.)+[a-zA-Z]{{2,}}$")
_LOCAL_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}
_LOCAL_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa")
_METADATA_HOSTS = {"169.254.169.254", "fd00:ec2::254", "100.100.100.200"}


def _reject(detail: str) -> HTTPException:
    return HTTPException(status_code=400, detail=detail)


def _normalize_ip(ip):
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        if ip.sixtofour is not None:
            return ip.sixtofour
    return ip


def is_forbidden_ip(ip) -> bool:
    ip = _normalize_ip(ip)
    return (
        not ip.is_global
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
        or str(ip) in _METADATA_HOSTS
    )


def _resolve(host: str) -> list:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        raise _reject("Target does not resolve to an IP address")
    addresses = []
    for info in infos:
        try:
            addresses.append(ipaddress.ip_address(info[4][0]))
        except ValueError:
            continue
    if not addresses:
        raise _reject("Target does not resolve to an IP address")
    return addresses


def validate_target(target: str, resolve: bool = True) -> str:
    target = (target or "").strip()
    if not target:
        raise _reject("Target is required")
    if len(target) > 253:
        raise _reject("Target too long")

    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        ip = None

    if ip is not None:
        if is_forbidden_ip(ip):
            raise _reject("Scanning internal, private, or reserved IP addresses is forbidden")
        return str(ip)

    host = target.rstrip(".").lower()
    if not _HOSTNAME.match(host):
        raise _reject("Invalid target. Must be a valid domain or public IP address")
    if host in _LOCAL_NAMES or host.endswith(_LOCAL_SUFFIXES):
        raise _reject("Scanning localhost or internal hostnames is forbidden")

    if resolve:
        for address in _resolve(host):
            if is_forbidden_ip(address):
                raise _reject("Target resolves to an internal or reserved IP address")
    return host


def resolve_target(target: str) -> tuple:
    """Validate a target and pin it to one resolved, approved IP literal.

    Returns ``(host, ip)``: ``host`` is what ``validate_target`` would return
    (an IP string, or the normalized hostname); ``ip`` is a single address
    from that resolution, already checked against the forbidden-IP rules.

    This exists because handing a validated *hostname* back to a scanner lets
    the scanner re-resolve it on its own, independently, whenever it actually
    runs. A target with a short-TTL DNS record can pass validation pointing at
    a public IP and then be repointed at an internal address (e.g. the cloud
    metadata IP) before the scanner's own lookup happens minutes later -
    classic DNS-rebinding TOCTOU. Callers that are about to hand a target to a
    scanner should call this immediately beforehand and use the returned
    ``ip``, not the hostname, wherever the scanned tool accepts a bare
    address.
    """
    host = validate_target(target, resolve=False)
    try:
        ip = ipaddress.ip_address(host)
        return host, str(ip)
    except ValueError:
        pass

    addresses = _resolve(host)
    for address in addresses:
        if is_forbidden_ip(address):
            raise _reject("Target resolves to an internal or reserved IP address")
    return host, str(addresses[0])
