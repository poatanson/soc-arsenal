"""table / json / csv 출력 포맷터."""
import csv
import json
import sys
from typing import Any, Dict, List, Optional, Sequence, TextIO


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return ",".join(str(v) for v in value)
    return str(value)


def emit(rows: List[Dict[str, Any]], fmt: str = "table",
         columns: Optional[Sequence[str]] = None, title: Optional[str] = None,
         out: TextIO = sys.stdout, max_width: int = 80) -> None:
    """dict 목록을 지정 형식으로 출력한다."""
    if columns is None:
        columns = list(rows[0].keys()) if rows else []

    if fmt == "json":
        json.dump([{c: r.get(c) for c in columns} for r in rows], out,
                  ensure_ascii=False, indent=2, default=str)
        out.write("\n")
        return

    if fmt == "csv":
        writer = csv.writer(out, lineterminator="\n")
        writer.writerow(columns)
        for r in rows:
            writer.writerow([_cell(r.get(c)) for c in columns])
        return

    if title:
        out.write(f"\n=== {title} ({len(rows)}) ===\n")
    if not rows:
        out.write("(결과 없음)\n")
        return
    table = [[_cell(r.get(c)) for c in columns] for r in rows]
    table = [[v if len(v) <= max_width else v[: max_width - 3] + "..." for v in row]
             for row in table]
    widths = [max(len(c), *(len(row[i]) for row in table)) for i, c in enumerate(columns)]
    out.write("  ".join(c.upper().ljust(w) for c, w in zip(columns, widths)).rstrip() + "\n")
    out.write("  ".join("-" * w for w in widths) + "\n")
    for row in table:
        out.write("  ".join(v.ljust(w) for v, w in zip(row, widths)).rstrip() + "\n")


def emit_sections(sections: Dict[str, List[Dict[str, Any]]], fmt: str = "table",
                  out: TextIO = sys.stdout) -> None:
    """여러 섹션을 한 번에 출력. json은 하나의 객체로, csv는 section 컬럼을 붙여 합친다."""
    if fmt == "json":
        json.dump(sections, out, ensure_ascii=False, indent=2, default=str)
        out.write("\n")
        return
    if fmt == "csv":
        for name, rows in sections.items():
            if not rows:
                continue
            emit([{"section": name, **r} for r in rows], "csv", out=out)
        return
    for name, rows in sections.items():
        emit(rows, "table", title=name, out=out)
