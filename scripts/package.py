"""Create a deterministic release payload and stamp its checksum in install.sh.

The payload excludes install.sh itself, avoiding a self-referential checksum.
Only explicit source directories are eligible for publication.
"""
import gzip
import hashlib
import io
from pathlib import Path
import re
import tarfile

ROOT = Path(__file__).resolve().parent.parent
VERSION = '1.0.0'


def main():
    build = ROOT / 'dist'
    build.mkdir(exist_ok=True)
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for directory in ('vpnkit', 'assets', 'LICENSE', 'THIRD_PARTY.md'):
            selected = ROOT / directory
            sources = [selected] if selected.is_file() else sorted(selected.rglob('*'))
            for source in sources:
                if not source.is_file() or '__pycache__' in source.parts or source.suffix == '.pyc':
                    continue
                if source.is_symlink():
                    raise RuntimeError(f'Refusing symlink: {source}')
                content = source.read_bytes()
                entry = tarfile.TarInfo(source.relative_to(ROOT).as_posix())
                entry.size = len(content)
                entry.mode = 0o644
                entry.mtime = 0
                archive.addfile(entry, io.BytesIO(content))
    data = gzip.compress(stream.getvalue(), mtime=0)
    checksum = hashlib.sha256(data).hexdigest()
    name = f'vpnkit-v{VERSION}.tar.gz'
    (build / name).write_bytes(data)
    (build / 'SHA256SUMS').write_text(f'{checksum}  {name}\n')
    bootstrap = ROOT / 'install.sh'
    script = re.sub(r"APP_SHA256='[^']+'", f"APP_SHA256='{checksum}'", bootstrap.read_text())
    bootstrap.write_text(script)
    print(f'{checksum}  {name}')


if __name__ == '__main__':
    main()
