#!/bin/zsh
# One button: sets up the Mac on first use, reads the iOS version from the iPhone, installs 2nd Data the first
# time and boots it every time after. You only put the phone into pwned DFU when asked.
cd "${0:A:h}" || exit 1
if ! [[ -x .venv/bin/python3 ]] || ! .venv/bin/python3 -c 'import importlib.util as u, sys; sys.exit(any(u.find_spec(m) is None for m in ("pyimg4", "usb", "pymobiledevice3")))' 2>/dev/null; then
    echo "First run: installing what the Mac needs (./setup.sh) ..."
    ./setup.sh || exit 1
fi
exec .venv/bin/python3 dualboot.py "$@"
