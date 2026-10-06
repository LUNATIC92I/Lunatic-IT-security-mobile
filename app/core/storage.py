"""Disk usage of the application data directory and temporary-files cleanup.

Only directories created by the application are measured. Symbolic links are
never followed (neither for measuring nor for deleting), so a link planted in a
data directory can neither inflate the figures nor redirect a deletion outside
the data directory.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from app.config import Settings
from app.logging_config import get_logger

log = get_logger("storage")


def directory_usage(path: Path) -> dict[str, int]:
    """Total size and file count of ``path`` (symlinks counted, never followed)."""
    total = files = 0
    if not path.is_dir():
        return {"bytes": 0, "files": 0}
    stack = [path]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                        else:
                            total += entry.stat(follow_symlinks=False).st_size
                            files += 1
                    except OSError:
                        continue
        except OSError as exc:
            log.warning("Cannot read %s: %s", current, exc.strerror or exc)
    return {"bytes": total, "files": files}


def storage_report(settings: Settings) -> dict[str, object]:
    folders = {
        "downloads": ("Images GrapheneOS", settings.downloads_dir),
        "backups": ("Sauvegardes", settings.backups_dir),
        "reports": ("Rapports d'audit", settings.reports_dir),
        "logs": ("Logs", settings.logs_dir),
        "tmp": ("Fichiers temporaires", settings.temp_dir),
    }
    items = []
    for key, (label, path) in folders.items():
        items.append({"key": key, "label": label, "path": str(path), **directory_usage(path)})
    data_dir = settings.resolved_data_dir
    disk = shutil.disk_usage(data_dir) if data_dir.exists() else None
    return {
        "data_dir": str(data_dir),
        "folders": items,
        "total_bytes": sum(item["bytes"] for item in items),
        "disk_free_bytes": disk.free if disk else None,
        "disk_total_bytes": disk.total if disk else None,
    }


def purge_temp(settings: Settings) -> dict[str, int]:
    """Delete everything inside the temporary directory (not the directory itself)."""
    temp = settings.temp_dir
    removed = freed = errors = 0
    if not temp.is_dir():
        return {"removed": 0, "freed_bytes": 0, "errors": 0}
    with os.scandir(temp) as entries:
        children = list(entries)
    for entry in children:
        path = Path(entry.path)
        try:
            if entry.is_dir(follow_symlinks=False):
                size = directory_usage(path)["bytes"]
                shutil.rmtree(path)
            else:
                size = entry.stat(follow_symlinks=False).st_size
                path.unlink()
            removed += 1
            freed += size
        except OSError as exc:
            errors += 1
            log.error("Cannot delete temporary entry %s: %s", entry.name, exc.strerror or exc)
    log.info("Temporary files purged: %d entr(y/ies), %d bytes freed, %d error(s)", removed, freed, errors)
    return {"removed": removed, "freed_bytes": freed, "errors": errors}
