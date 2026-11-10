import binascii
import hashlib
import os
import re


class SetupError(ValueError):
    pass


_HEADER = re.compile(
    r"(?m)^TICKET dir=([0-9A-Fa-f]{96}) len=(\d+) sha384=([0-9A-Fa-f]{96}) crc=([0-9A-Fa-f]{8})$"
)
_TICKET_NAME = re.compile(r"apticket-([0-9A-Fa-f]{16})\.der$")


def _install_log(data, build):
    log = data.decode('latin1')
    if not re.search(r"(?m)^===== dualboot setup ramdisk v\d+ \(INSTALL\) =====$", log):
        raise SetupError('this is not a doublera1n install setup log')
    builds = re.findall(r"(?m)^SYSBUILD (\S+) SYSVER (\S+)$", log)
    if len(builds) != 1 or (build is not None and builds[0][0] != build):
        raise SetupError(f"phone System build {builds[0][0] if builds else '?'} does not match {build}")
    return log


def inspect_setup_log(data, build, fetch_data=None):
    setup = _install_log(data, None if fetch_data is not None else build)
    log = _install_log(fetch_data, build) if fetch_data is not None else setup
    if not re.search(r"(?m)^\s*copyfile -> 0 \(ok\)", setup):
        raise SetupError('DataB template copy did not report success')
    if fetch_data is not None and 'DataB already set up - template copy skipped' not in log:
        raise SetupError('rerun log does not show DataB reuse')
    count = re.findall(r"(?m)^tickets dumped: (\d+)$", log)
    if not count or int(count[-1]) < 1:
        raise SetupError('setup did not finish dumping the installed ticket')
    headers = []
    for directory, length, digest, crc in _HEADER.findall(log):
        directory, digest = directory.upper(), digest.upper()
        if int(length) <= 0 or int(length) > 65536:
            raise SetupError('invalid ticket size in setup log')
        if directory != digest:
            raise SetupError('Preboot directory differs from the ticket SHA-384')
        if not re.search(rf'(?m)^TICKET END {digest}$', log):
            raise SetupError('ticket dump did not finish')
        if not re.search(rf'(?im)^saved /mnt2/jb/apticket-{directory[:16]}\.der$', log):
            raise SetupError('ticket was not saved on DataB')
        headers.append((directory, int(length), digest, int(crc, 16)))
    if len(headers) != int(count[-1]):
        raise SetupError('setup log has an incomplete ticket list')
    return headers


def validate_ticket(data, metadata, ecid, profile):
    directory, length, digest, crc = metadata
    if len(data) != length or hashlib.sha384(data).hexdigest().upper() != digest:
        raise SetupError('ticket length or SHA-384 does not match the setup log')
    if binascii.crc32(data) != crc:
        raise SetupError('ticket CRC32 does not match the setup log')
    try:
        from pyimg4 import IM4M
        ticket = IM4M(data)
    except Exception as exc:
        raise SetupError(f'ticket is not a valid IM4M: {exc}') from exc
    if ticket.ecid != int(ecid, 16):
        raise SetupError('ticket ECID does not match this workspace')
    if ticket.chip_id != int(profile['cpid'], 16) or ticket.board_id != int(profile['bdid'], 16):
        raise SetupError('ticket chip or board does not match this profile')
    return directory


def select_ticket(log_bytes, candidates, ecid, profile, fetch_bytes=None):
    headers = inspect_setup_log(log_bytes, profile['build'], fetch_bytes)
    valid = []
    errors = []
    for name, data in candidates.items():
        match = _TICKET_NAME.fullmatch(os.path.basename(name))
        if not match:
            continue
        for item in headers:
            if item[0].startswith(match.group(1).upper()):
                try:
                    directory = validate_ticket(data, item, ecid, profile)
                    valid.append((directory, data))
                except SetupError as exc:
                    errors.append(f'{name}: {exc}')
    if len(valid) != 1:
        why = '; '.join(errors[:3]) if errors else 'no matching ticket file'
        raise SetupError(f'need exactly one matching installed ticket, found {len(valid)} ({why})')
    return valid[0]
