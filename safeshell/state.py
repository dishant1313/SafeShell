import hashlib
import os
import subprocess
from datetime import datetime, timezone
from typing import List, Optional

from safeshell.schemas import CoreRequest, FileEntry, StateManifest, new_id


def backend() -> str:
    if os.environ.get("SAFESHELL_DISABLE_CORE") == "1":
        return "python"
    core_bin = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "core",
        "target",
        "debug",
        "safeshell-core",
    )
    if os.path.exists(core_bin):
        return "core"
    return "python"


def collect_state_core(
    paths: List[str], services: Optional[List[str]] = None, max_files: int = 5000
) -> StateManifest:
    from safeshell.executor import call_core, raise_for_error

    params = {"paths": paths, "services": services or [], "max_files": max_files}
    req = CoreRequest(op="collect_state", params=params)
    try:
        resp = call_core(req)
        raise_for_error(resp)
        data = resp.data
        files = [FileEntry(**f) for f in data["files"]]
        return StateManifest(
            manifest_id=data["manifest_id"],
            collected_at=datetime.now(timezone.utc),
            files=files,
            services=data.get("services", {}),
            truncated=data.get("truncated", False),
        )
    except Exception as e:
        import logging

        logging.warning(f"Core state collection failed: {e}. Falling back to python.")
        return collect_state_python(paths, services, max_files)


def collect_state_python(
    paths: List[str], services: Optional[List[str]] = None, max_files: int = 5000
) -> StateManifest:
    file_entries = []
    truncated = False
    count = 0
    sorted_paths = sorted(paths)
    for p in sorted_paths:
        if not os.path.exists(p) and not os.path.islink(p):
            file_entries.append(
                FileEntry(path=p, sha256="", mode=0, uid=0, gid=0, size=0, exists=False)
            )
            continue
        if os.path.isfile(p):
            if count >= max_files:
                truncated = True
                break
            try:
                st = os.lstat(p)
                sha256 = hashlib.sha256()
                with open(p, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        sha256.update(chunk)
                file_entries.append(
                    FileEntry(
                        path=p,
                        sha256=sha256.hexdigest(),
                        mode=st.st_mode,
                        uid=st.st_uid,
                        gid=st.st_gid,
                        size=st.st_size,
                        exists=True,
                    )
                )
                count += 1
            except Exception:
                pass
        elif os.path.islink(p):
            if count >= max_files:
                truncated = True
                break
            st = os.lstat(p)
            file_entries.append(
                FileEntry(
                    path=p,
                    sha256="symlink",
                    mode=st.st_mode,
                    uid=st.st_uid,
                    gid=st.st_gid,
                    size=st.st_size,
                    exists=True,
                )
            )
            count += 1
        elif os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                # Dont walk into symlinks
                dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
                for file in sorted(files):
                    if count >= max_files:
                        truncated = True
                        break
                    full_path = os.path.join(root, file)
                    try:
                        st = os.lstat(full_path)
                        if os.path.islink(full_path):
                            file_entries.append(
                                FileEntry(
                                    path=full_path,
                                    sha256="symlink",
                                    mode=st.st_mode,
                                    uid=st.st_uid,
                                    gid=st.st_gid,
                                    size=st.st_size,
                                    exists=True,
                                )
                            )
                            count += 1
                            continue
                        if not os.path.isfile(full_path):
                            continue
                        sha256 = hashlib.sha256()
                        with open(full_path, "rb") as f:
                            for chunk in iter(lambda: f.read(65536), b""):
                                sha256.update(chunk)
                        file_entries.append(
                            FileEntry(
                                path=full_path,
                                sha256=sha256.hexdigest(),
                                mode=st.st_mode,
                                uid=st.st_uid,
                                gid=st.st_gid,
                                size=st.st_size,
                                exists=True,
                            )
                        )
                        count += 1
                    except Exception:
                        pass
                if truncated:
                    break
        if truncated:
            break

    service_states = {}
    if services:
        for srv in services:
            try:
                res = subprocess.run(
                    ["systemctl", "is-active", srv], capture_output=True, text=True, timeout=2
                )
                state = res.stdout.strip()
                if not state:
                    state = "unknown"
                service_states[srv] = state
            except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
                service_states[srv] = "unknown"

    # Sort files to match Rust deterministic order
    file_entries.sort(key=lambda x: x.path)

    return StateManifest(
        manifest_id=new_id("man"),
        collected_at=datetime.now(timezone.utc),
        files=file_entries,
        services=service_states,
        truncated=truncated,
    )


def collect_state(
    paths: List[str], services: Optional[List[str]] = None, max_files: int = 5000
) -> StateManifest:
    if backend() == "core":
        return collect_state_core(paths, services, max_files)
    return collect_state_python(paths, services, max_files)
