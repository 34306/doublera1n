"""dualboot patch finder: semantic resolvers for the kernel, TXM and daemon patches of a given iOS build.

Every patch site is rediscovered in the binary of THAT build (instruction shapes, strings, symbols, ObjC metadata);
offsets are outputs, never inputs. Each resolver demands a unique match and records the original bytes, so a changed
build fails loudly instead of being patched in the wrong place.

Output records have the shape component, id, offset, originalBytes, replacementBytes, summary, evidence.
Entry point: resolve.py (CLI and resolve_plan()); binary-analysis API: core.py; Objective-C metadata: objc.py.
"""
