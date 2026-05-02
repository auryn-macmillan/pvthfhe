#!/usr/bin/env python3
# pyright: reportAny=false, reportUnknownMemberType=false

import json
import math
import pathlib
import sys
from collections.abc import Mapping, Sequence


def load_points(paths: Sequence[str]) -> list[tuple[int, float, str]]:
    points: list[tuple[int, float, str]] = []
    raw_path: str
    for raw_path in paths:
        path = pathlib.Path(raw_path)
        with path.open("r", encoding="utf-8") as handle:
            raw_payload: object = json.load(handle)
        if not isinstance(raw_payload, Mapping):
            raise ValueError(f"expected JSON object in {path}")
        fold_count = parse_int(raw_payload.get("fold_count"), "fold_count", path)
        per_fold_ms = parse_float(raw_payload.get("per_fold_ms"), "per_fold_ms", path)
        points.append((fold_count, per_fold_ms, path.name))
    return sorted(points)


def parse_int(value: object, field: str, path: pathlib.Path) -> int:
    if isinstance(value, bool) or value is None:
        raise ValueError(f"expected integer-like {field} in {path}")
    if isinstance(value, (int, float, str)):
        return int(value)
    raise ValueError(f"expected integer-like {field} in {path}")


def parse_float(value: object, field: str, path: pathlib.Path) -> float:
    if isinstance(value, bool) or value is None:
        raise ValueError(f"expected float-like {field} in {path}")
    if isinstance(value, (int, float, str)):
        return float(value)
    raise ValueError(f"expected float-like {field} in {path}")


def fit_slope(points: Sequence[tuple[int, float, str]]) -> tuple[float, float]:
    xs = [math.log(point[0]) for point in points]
    ys = [math.log(point[1]) for point in points]
    mean_x = sum(xs) / len(xs)
    mean_y = sum(ys) / len(ys)
    numerator = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    denominator = sum((x - mean_x) ** 2 for x in xs)
    slope = numerator / denominator
    intercept = mean_y - slope * mean_x
    return slope, intercept


def main(argv: Sequence[str]) -> int:
    if len(argv) < 2:
        print("usage: fit-loglog.py bench/results/folding-*.json", file=sys.stderr)
        return 2

    points = load_points(argv[1:])
    if len(points) < 2:
        print("need at least two result files", file=sys.stderr)
        return 2

    slope, intercept = fit_slope(points)
    print("log-log fit for per_fold_ms vs fold_count")
    for fold_count, per_fold_ms, name in points:
        predicted = math.exp(intercept) * (fold_count ** slope)
        print(f"- {name}: N={fold_count} per_fold_ms={per_fold_ms:.6f} predicted={predicted:.6f}")
    print(f"slope={slope:.6f}")
    print(f"intercept={intercept:.6f}")
    print(f"sublinear={str(slope < 0.5).lower()}")
    return 0 if slope < 0.5 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
