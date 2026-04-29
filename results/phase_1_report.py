import re
from pathlib import Path
from typing import Iterable, List, Tuple


_TIMESTAMP_PATTERN = re.compile(r":\s*([0-9]+(?:\.[0-9]+)?)\s*:")


def _extract_timestamp(line: str) -> float | None:
    matches = list(_TIMESTAMP_PATTERN.finditer(line))
    if not matches:
        return None
    match = matches[-1]
    try:
        return float(match.group(1))
    except ValueError:
        return None


def _read_lines(path: Path) -> Iterable[str]:
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8").splitlines()


def write_phase_1_report(
    ids_path: Path | str = "logs/ids.stderr",
    napt_path: Path | str = "logs/napt.stderr",
    output_path: Path | str = "results/phase_1_report",
) -> None:

    # TODO: add the path for the load balancer
    ids_path = Path(ids_path)
    napt_path = Path(napt_path)
    output_path = Path(output_path)
    if output_path.exists():
        output_path.unlink()

    lines: List[Tuple[float | None, int, str]] = []
    sequence = 0
    for line in _read_lines(ids_path):
        lines.append((_extract_timestamp(line), sequence, line))
        sequence += 1
    for line in _read_lines(napt_path):
        lines.append((_extract_timestamp(line), sequence, line))
        sequence += 1

    lines.sort(key=lambda item: (item[0] is None, item[0] if item[0] is not None else 0.0, item[1]))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(line for _, _, line in lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    write_phase_1_report()
