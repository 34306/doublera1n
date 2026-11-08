"""In-process access to lib/patchfinder: resolve one plan of a firmware component and return JSON-shaped records.

    resolve('kernel', 'boot-jit', '/path/kernelcache.release.iphone12')   -> [{'id', 'offset', ...}, ...]
    resolve('userland', 'mobileactivationd', '/rootfs/usr/libexec/mobileactivationd')
    version()  -> 'patchfinder-<12 hex>' (hash of the resolver sources, recorded in every profile)

Every record's original bytes are checked in the input before it is returned.
"""
import hashlib, os, sys

PF = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'patchfinder')
if PF not in sys.path:
    sys.path.insert(0, PF)
import core as _core          # noqa: E402  (flat imports, like resolve.py)
import resolve as _resolve    # noqa: E402


def resolve(component, plan, path):
    image = _core.load_image(path)
    records = _resolve.resolve_plan(component, plan, image)
    _resolve.verify_preimages(records, image)
    return [r.to_json() for r in records]


def version():
    h = hashlib.sha256()
    for f in sorted(os.listdir(PF)):
        if f.endswith('.py'):
            h.update(f.encode() + b'\0' + open(os.path.join(PF, f), 'rb').read())
    return 'patchfinder-' + h.hexdigest()[:12]
