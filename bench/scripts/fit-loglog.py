#!/usr/bin/env python3
"""Fit a log-log slope for scaling results and assert sub-quadratic per-party growth."""

# pyright: reportAny=false, reportUnknownMemberType=false

import json
import math
import pathlib
import sys
from collections.abc import Mapping, Sequence

DEFAULT_RESULTS = [
    "bench/results/scaling-n128.json",
    "bench/results/scaling-n256.json",
    "bench/results/scaling-n512.json",
    "bench/results/scaling-n1024.json",
]


def load_points(paths: Sequence[str]) -> list[tuple[int, float, str]]:
    points: list[tuple[int, float, str]] = []
    raw_path: str
    for raw_path in paths:
        path = pathlib.Path(raw_path)
        with path.open("r", encoding="utf-8") as handle:
            raw_payload: object = json.load(handle)
        if not isinstance(raw_payload, Mapping):
            raise ValueError(f"expected JSON object in {path}")
        fold_count = parse_int(
            raw_payload.get("fold_count", raw_payload.get("n")),
            "fold_count/n",
            path,
        )
        work_metric_ms = parse_work_metric_ms(raw_payload, fold_count, path)
        points.append((fold_count, work_metric_ms, path.name))
    return sorted(points)


def parse_work_metric_ms(payload: Mapping[object, object], fold_count: int, path: pathlib.Path) -> float:
    if "per_fold_ms" in payload:
        return parse_float(payload.get("per_fold_ms"), "per_fold_ms", path)
    total_ms = parse_float(
        payload.get("aggregate_wall_ms", payload.get("aggregator_wall_ms")),
        "aggregate_wall_ms/aggregator_wall_ms",
        path,
    )
    return total_ms / fold_count


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
    paths = list(argv[1:]) or DEFAULT_RESULTS

    points = load_points(paths)
    if len(points) < 2:
        print("need at least two result files", file=sys.stderr)
        return 2

    slope, intercept = fit_slope(points)
    print("log-log fit for per-party work metric vs n")
    for fold_count, work_metric_ms, name in points:
        predicted = math.exp(intercept) * (fold_count ** slope)
        print(
            f"- {name}: n={fold_count} per_party_ms={work_metric_ms:.6f} predicted={predicted:.6f}"
        )
    print(f"log-log slope (exponent): {slope:.3f}")
    if slope >= 2.0:
        print(f"sub-quadratic per-party growth: FAILED (slope {slope:.3f} >= 2.0)", file=sys.stderr)
        return 1
    print("sub-quadratic per-party growth: CONFIRMED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
