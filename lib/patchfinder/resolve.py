#!/usr/bin/env python3
"""Resolve the patch sites of one plan in a firmware component and print the records (nothing is modified).

usage: resolve.py <kernel|txm|userland> <plan> <input> [--json] [--only PREFIX[,PREFIX...]]

  input   an IM4P (kernelcache / TXM from an IPSW; the payload is decompressed) or a raw thin Mach-O
          (a daemon from the root filesystem). Record offsets are offsets into that payload / file.
  --json  print the records as a JSON list of {component, id, offset, originalBytes, replacementBytes, summary,
          evidence} (offset decimal, bytes lowercase hex)
  --only  keep only records whose id starts with one of the comma-separated prefixes; resolver families that
          cannot emit such ids are not run at all (so families that are not implemented yet do not block)

Plans are ordered lists of resolver families (PLANS below); the record order is the plan order.
Exit status: 0 ok, 1 resolver or input error, 2 usage error, 3 a family the plan needs is not implemented yet.

Library use: resolve_plan(component, plan, image, only=()) -> [core.PatchRecord].
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Dict, List, NamedTuple, Sequence

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)       # `python3 -I` does not put the script directory on sys.path

import core            # noqa: E402
import kernel_cm       # noqa: E402
import kernel_policy   # noqa: E402
import kernel_restore  # noqa: E402
import txm             # noqa: E402
import userland        # noqa: E402

EXIT_ERROR, EXIT_USAGE, EXIT_NOT_IMPLEMENTED = 1, 2, 3


class Step(NamedTuple):
    """One resolver family call inside a plan: module.<name>(image) -> [PatchRecord]."""
    module: object
    name: str

    @property
    def prefixes(self) -> Sequence[str]:
        return self.module.PREFIXES[self.name]

    @property
    def label(self) -> str:
        return f'{self.module.__name__}.{self.name}'

    def __call__(self, image: core.BinaryImage) -> List[core.PatchRecord]:
        return getattr(self.module, self.name)(image)


def _steps(*pairs) -> List[Step]:
    return [Step(module, name) for module, name in pairs]


# Kernel restore plan: identity + panic + AMFI + profile-gated PPL trust cache.
KERNEL_RESTORE = _steps(
    (kernel_restore, 'identity'),
    (kernel_restore, 'panic'),
    (kernel_restore, 'amfi'),
    (kernel_restore, 'ppl_trust_cache_required'),
)
# Normal-boot compatibility plan: restore + boot policy + SEP (AKS, then SEP silencing) + credential manager
# + Sandbox without the scoped vnode-open shim + Valeria (profile may omit it).
KERNEL_BOOT_COMPATIBILITY = KERNEL_RESTORE + _steps(
    (kernel_policy, 'boot_policy'),
    (kernel_policy, 'aks'),
    (kernel_policy, 'sep_silence'),
    (kernel_cm, 'credential_manager'),
    (kernel_policy, 'sandbox_compatibility'),
    (kernel_cm, 'valeria_composite'),
)
# JIT plan: compatibility + profile-gated code-signing patches + exception-port enforcement byte.
KERNEL_BOOT_JIT = KERNEL_BOOT_COMPATIBILITY + _steps(
    (kernel_policy, 'codesigning_required'),
    (kernel_policy, 'exception_port'),
)
# TXM boot-permissive: restore (query module + constraints) + boot state + the two address-space debug-mapping
# branches + permissive flags.
TXM_BOOT_PERMISSIVE = _steps(
    (txm, 'query_module'),
    (txm, 'constraints'),
    (txm, 'boot_state'),
    (txm, 'debug_mapping_mark_branches'),
    (txm, 'permissive_flags'),
)

PLANS: Dict[str, Dict[str, List[Step]]] = {
    'kernel': {
        'restore': KERNEL_RESTORE,
        'boot-jit': KERNEL_BOOT_JIT,
        'vm-fault-cs-bypass': _steps((kernel_policy, 'vm_fault_cs_bypass')),
    },
    'txm': {
        'boot-permissive': TXM_BOOT_PERMISSIVE,
    },
    'userland': {
        'commcenter': _steps((userland, 'commcenter')),
        'coreauthd': _steps((userland, 'coreauthd')),
        'ctkd': _steps((userland, 'ctkd')),
        'mobileactivationd': _steps((userland, 'mobileactivationd')),
    },
}

# A typo in a plan table should fail at import, not halfway through a kernel scan.
for _plans in PLANS.values():
    for _plan in _plans.values():
        for _step in _plan:
            assert callable(getattr(_step.module, _step.name, None)), _step.label
            assert _step.name in _step.module.PREFIXES, _step.label


class NotImplementedFamilyError(Exception):
    """A plan step whose resolver family still raises NotImplementedError."""

    def __init__(self, step: Step, detail: str):
        super().__init__(f'{step.label} is not implemented yet ({detail})' if detail and detail != step.label
                         else f'{step.label} is not implemented yet')
        self.step = step


def _may_emit(step: Step, only: Sequence[str]) -> bool:
    return any(p.startswith(o) or o.startswith(p) for p in step.prefixes for o in only)


def resolve_plan(component: str, plan: str, image: core.BinaryImage, only: Sequence[str] = ()) -> List[core.PatchRecord]:
    """Run a plan's families in order. With `only`, families that cannot emit a matching id are skipped and the
    result is filtered by id prefix. Raises core.PatchfinderError, NotImplementedFamilyError or KeyError (unknown plan)."""
    only = tuple(only)
    records: List[core.PatchRecord] = []
    for step in PLANS[component][plan]:
        if only and not _may_emit(step, only):
            continue
        try:
            records.extend(step(image))
        except NotImplementedError as error:
            raise NotImplementedFamilyError(step, str(error)) from None
    if only:
        records = [r for r in records if r.id.startswith(only)]
    return records


def verify_preimages(records: Sequence[core.PatchRecord], image: core.BinaryImage) -> None:
    """Every record must describe bytes that are really at its offset (catches resolver bugs before output)."""
    for record in records:
        if len(record.original_bytes) != len(record.replacement_bytes) or not record.original_bytes:
            raise core.PatchfinderError.invalid_patch(record.id, 'original and replacement lengths differ or are empty')
        found = image.bytes_at(record.offset, len(record.original_bytes))
        if found != record.original_bytes:
            raise core.PatchfinderError.preimage_mismatch(record.id, record.offset, record.original_bytes, found)


def report_profile(image: core.BinaryImage, stream=sys.stderr) -> None:
    profile = core.detect_kernel_profile(image)
    if profile is None:
        print('firmware profile: unidentified', file=stream)
    else:
        builds = ', '.join(profile.builds)
        print(f'firmware profile: {profile.id} (iOS {profile.product_version}; build{"s" if len(profile.builds) > 1 else ""}'
              f' {builds})', file=stream)


def format_records(records: Sequence[core.PatchRecord], as_json: bool) -> str:
    if as_json:
        return core.encode_records(records)
    return ''.join(f'{r.component} {r.id}: 0x{r.offset:x} {r.original_bytes.hex()} -> {r.replacement_bytes.hex()}\n'
                   for r in records)


def _plan_listing() -> str:
    return '\n'.join(f'  {component:<9} {", ".join(sorted(plans))}' for component, plans in PLANS.items())


def main(argv: Sequence[str] = None) -> int:
    parser = argparse.ArgumentParser(
        prog='resolve.py', formatter_class=argparse.RawDescriptionHelpFormatter,
        description='Resolve patch sites in a firmware component and print them, changing nothing.',
        epilog='components and plans:\n' + _plan_listing())
    parser.add_argument('component', help='firmware component')
    parser.add_argument('plan', help='patch plan for that component')
    parser.add_argument('input', help='IM4P or raw payload to read')
    parser.add_argument('--json', action='store_true', help='emit records as JSON')
    parser.add_argument('--only', default='', metavar='PREFIX[,PREFIX...]',
                        help='keep only records whose id starts with one of these prefixes')
    args = parser.parse_args(argv)

    plans = PLANS.get(args.component)
    if plans is None:
        parser.error(f"unknown component '{args.component}'. Components: {', '.join(sorted(PLANS))}")
    if args.plan not in plans:
        parser.error(f"unknown plan '{args.plan}' for {args.component}. Plans: {', '.join(sorted(plans))}")
    only = tuple(p.strip() for p in args.only.split(',') if p.strip())

    try:
        image = core.load_image(args.input)
        if args.component == 'kernel':
            report_profile(image)
        records = resolve_plan(args.component, args.plan, image, only)
        verify_preimages(records, image)
    except NotImplementedFamilyError as error:
        print(f'Error: {error}', file=sys.stderr)
        return EXIT_NOT_IMPLEMENTED
    except core.PatchfinderError as error:
        print(f'Error: {error}', file=sys.stderr)
        return EXIT_ERROR
    except OSError as error:
        print(f'Error: {error}', file=sys.stderr)
        return EXIT_ERROR

    sys.stdout.write(format_records(records, args.json))
    return 0


if __name__ == '__main__':
    sys.exit(main())
