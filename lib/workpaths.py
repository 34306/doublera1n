import os
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKROOT = os.path.abspath(os.path.expanduser(
    os.environ.get('DUALBOOT_HOME') or str(REPO_ROOT / 'dualboot-work')))
