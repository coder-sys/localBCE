"""Reproduce the nonactivating M31 Brakedown distance schedule.

This evaluates the entropy, convexity, and unique-neighbour bounds used in
IACR 2023/769 at the real B=16 K128 row geometry.  It does not turn a sampled
matrix into a deterministic distance certificate and does not qualify a PCS.

The paper's worked lambda=110 control allocates lambda+log2(K)+1 bits across
K recursive levels.  Equation (18) contains four separately union-bounded
events per level, so Blind Ledger deliberately uses the more conservative
lambda+log2(K)+2 allocation.  No security credit depends on resolving that
one-bit textual ambiguity in the optimistic direction.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


FIELD_MODULUS = (1 << 31) - 1
LOG_FIELD = math.log2(FIELD_MODULUS)
TOP_ROWS = 1 << 24
BASE_MAX_ROWS = 512
RATE = 0.704
ALPHA = 0.11
RELATIVE_DISTANCE = 0.02
NOMINAL_GAMMA = 0.01 * RELATIVE_DISTANCE
TARGET_SECURITY_BITS = 392
FAILURE_COMPONENTS_PER_LEVEL = 4
EXPECTED_FACTOR_DEGREES = (26, 32, 42, 65, 116)
EXPECTED_OUTER_DEGREES = (21, 21, 21, 23, 43)
EXPECTED_BASE_ROWS = 270
EXPECTED_BASE_CODEWORD_ROWS = 384


def entropy(value: float) -> float:
    if value <= 0.0 or value >= 1.0:
        return 0.0
    return (
        -value * math.log2(value)
        - (1.0 - value) * math.log2(1.0 - value)
    )


def entropy_derivative(value: float) -> float:
    return math.log2((1.0 - value) / value)


def log2_binomial(n: int, k: int) -> float:
    if k < 0 or k > n:
        return float("-inf")
    return (
        math.lgamma(n + 1)
        - math.lgamma(k + 1)
        - math.lgamma(n - k + 1)
    ) / math.log(2.0)


@dataclass(frozen=True)
class Line:
    intercept: float
    slope: float

    def at(self, value: float) -> float:
        return self.intercept + self.slope * value


@dataclass(frozen=True)
class Level:
    rows: int
    factor_rows: int
    codeword_rows: int
    inner_codeword_rows: int
    outer_rows: int
    factor_degree: int
    outer_degree: int


def tangent(value: float, derivative: float, at: float) -> Line:
    return Line(value - derivative * at, derivative)


def graph_degree_bound(
    n: int,
    m: int,
    security_bits: float,
    line: Line,
    left: float,
    right: float,
) -> int | None:
    ratio = m / n

    def f1(value: float) -> float:
        ell = line.at(value)
        return security_bits / n + entropy(value) + ratio * entropy(ell)

    def f2(value: float) -> float:
        return -value * math.log2(line.at(value))

    def g1(value: float) -> float:
        ell = line.at(value)
        return (
            1.0 / (1.0 - value)
            + ratio
            * line.slope
            * line.slope
            * value
            / ell
            / (1.0 - ell)
        )

    def g2_without_degree(value: float) -> float:
        ell = line.at(value)
        return line.slope * value / ell * (1.0 + line.intercept / ell)

    if (
        line.intercept < 0.0
        or line.slope < 0.0
        or line.at(left) <= 0.0
        or line.at(right) >= 1.0
    ):
        return None
    denominator = g2_without_degree(left)
    if denominator <= 0.0:
        return None
    bound = max(
        g1(right) / denominator,
        f1(left) / f2(left),
        f1(right) / f2(right),
    )
    return math.ceil(bound - 1e-12)


def factor_line(
    n: int,
    m: int,
    security_bits: float,
    tangent_point: float,
) -> Line:
    ratio = m / n
    value = (
        tangent_point
        + (security_bits / n + entropy(tangent_point)) / LOG_FIELD
    ) / ratio
    derivative = (
        1.0 + entropy_derivative(tangent_point) / LOG_FIELD
    ) / ratio
    return tangent(value, derivative, tangent_point)


def outer_line(
    n: int,
    m: int,
    security_bits: float,
    beta: float,
    tangent_point: float,
) -> Line:
    ratio = n / m
    value = ratio * (
        tangent_point
        + beta
        + (security_bits / n + entropy(tangent_point)) / LOG_FIELD
    ) + 1.0 / LOG_FIELD
    derivative = ratio * (
        1.0 + entropy_derivative(tangent_point) / LOG_FIELD
    )
    return tangent(value, derivative, tangent_point)


def factor_small_case_degree(
    n: int,
    m: int,
    security_bits: float,
    gamma: float,
    maximum_degree: int = 512,
) -> int | None:
    stop = max(1, math.floor(gamma * n))
    for degree in range(5, maximum_degree + 1):
        valid = True
        for weight in range(1, stop + 1):
            # Spielman expansion is strictly greater than degree*weight/2.
            expansion = math.floor(degree * weight / 2.0)
            if expansion < 1 or expansion >= m:
                valid = False
                break
            graph_log_probability = (
                log2_binomial(n, weight)
                + log2_binomial(m, expansion)
                + weight
                * (
                    log2_binomial(expansion, degree)
                    - log2_binomial(m, degree)
                )
            )
            if graph_log_probability > -security_bits:
                valid = False
                break
        if valid:
            return degree
    return None


def best_factor_degree(
    n: int,
    m: int,
    security_bits: float,
    gamma: float,
    right: float,
) -> int | None:
    best: tuple[int, float] | None = None
    for step in range(1001):
        point = gamma + (right - gamma) * step / 1000.0
        line = factor_line(n, m, security_bits, point)
        degree = graph_degree_bound(
            n,
            m,
            security_bits,
            line,
            gamma,
            right,
        )
        if degree is None:
            continue
        candidate = (degree, point)
        if best is None or candidate < best:
            best = candidate
    return None if best is None else best[0]


def level_degrees(
    rows: int,
    component_security_bits: float,
) -> tuple[int, int, int, int, int, int]:
    factor_rows = round(ALPHA * rows)
    inner_codeword_rows = math.ceil(factor_rows / RATE)
    codeword_rows = math.ceil(rows / RATE)
    outer_rows = codeword_rows - rows - inner_codeword_rows
    gamma = max(NOMINAL_GAMMA, 1.0 / rows)
    small = (
        None
        if NOMINAL_GAMMA * rows < 1.0
        else factor_small_case_degree(
            rows,
            factor_rows,
            component_security_bits,
            NOMINAL_GAMMA,
            maximum_degree=min(factor_rows - 1, 512),
        )
    )
    large = best_factor_degree(
        rows,
        factor_rows,
        component_security_bits,
        gamma,
        RELATIVE_DISTANCE / RATE,
    )
    if large is None:
        raise RuntimeError("no admissible factor-map tangent")
    factor_degree = max(small or 0, large)
    beta = RELATIVE_DISTANCE * (1.0 - ALPHA) / ALPHA
    line = outer_line(
        inner_codeword_rows,
        outer_rows,
        component_security_bits,
        beta,
        RELATIVE_DISTANCE,
    )
    outer_degree = graph_degree_bound(
        inner_codeword_rows,
        outer_rows,
        component_security_bits,
        line,
        RELATIVE_DISTANCE,
        RELATIVE_DISTANCE / ALPHA,
    )
    if outer_degree is None:
        raise RuntimeError("no admissible outer-code tangent")
    return (
        factor_rows,
        codeword_rows,
        inner_codeword_rows,
        outer_rows,
        factor_degree,
        outer_degree,
    )


def recursion_rows(top_rows: int = TOP_ROWS) -> tuple[list[int], int]:
    levels = []
    rows = top_rows
    while rows > BASE_MAX_ROWS:
        levels.append(rows)
        rows = round(ALPHA * rows)
    return levels, rows


def component_security_bits(
    target_security_bits: int,
    level_count: int,
    failure_components_per_level: int,
) -> float:
    return target_security_bits + math.log2(
        level_count * failure_components_per_level
    )


def schedule() -> tuple[list[Level], int, int, float]:
    rows_per_level, base_rows = recursion_rows()
    allocated_bits = component_security_bits(
        TARGET_SECURITY_BITS,
        len(rows_per_level),
        FAILURE_COMPONENTS_PER_LEVEL,
    )
    levels = []
    for rows in rows_per_level:
        (
            factor_rows,
            codeword_rows,
            inner_codeword_rows,
            outer_rows,
            factor_degree,
            outer_degree,
        ) = level_degrees(rows, allocated_bits)
        levels.append(
            Level(
                rows=rows,
                factor_rows=factor_rows,
                codeword_rows=codeword_rows,
                inner_codeword_rows=inner_codeword_rows,
                outer_rows=outer_rows,
                factor_degree=factor_degree,
                outer_degree=outer_degree,
            )
        )
    return levels, base_rows, math.ceil(base_rows / RATE), allocated_bits


def assert_paper_control() -> None:
    # IACR 2023/769 section 7 reports c=8,d=21 for the 2^28,
    # lambda=110 control under its lambda+log2(K)+1 allocation.
    rows = 1 << 28
    paper_component_bits = 110 + math.log2(4) + 1.0
    *_, factor_degree, outer_degree = level_degrees(
        rows,
        paper_component_bits,
    )
    assert factor_degree == 8
    assert outer_degree == 21


def main() -> None:
    assert_paper_control()
    levels, base_rows, base_codeword_rows, allocated_bits = schedule()
    factor_degrees = tuple(level.factor_degree for level in levels)
    outer_degrees = tuple(level.outer_degree for level in levels)
    assert factor_degrees == EXPECTED_FACTOR_DEGREES
    assert outer_degrees == EXPECTED_OUTER_DEGREES
    assert base_rows == EXPECTED_BASE_ROWS
    assert base_codeword_rows == EXPECTED_BASE_CODEWORD_ROWS
    assert 2.0 ** -allocated_bits * (
        len(levels) * FAILURE_COMPONENTS_PER_LEVEL
    ) <= 2.0 ** -TARGET_SECURITY_BITS

    print("scope=m31_brakedown_recursive_distance_parameters")
    print("evidence_class=published_bound_reproduction")
    print("activation=false")
    print(f"target_security_bits={TARGET_SECURITY_BITS}")
    print(f"recursive_levels={len(levels)}")
    print(
        "conservative_failure_components_per_level="
        f"{FAILURE_COMPONENTS_PER_LEVEL}"
    )
    print(f"component_security_bits={allocated_bits:.6f}")
    print("paper_lambda_110_control_passed=true")
    for index, level in enumerate(levels):
        print(
            f"level={index} rows={level.rows} "
            f"factor_rows={level.factor_rows} "
            f"codeword_rows={level.codeword_rows} "
            f"inner_codeword_rows={level.inner_codeword_rows} "
            f"outer_rows={level.outer_rows} "
            f"factor_degree={level.factor_degree} "
            f"outer_degree={level.outer_degree}"
        )
    print(f"base_rows={base_rows}")
    print(f"base_codeword_rows={base_codeword_rows}")
    print(
        "factor_degrees="
        + ",".join(str(degree) for degree in factor_degrees)
    )
    print(
        "outer_degrees="
        + ",".join(str(degree) for degree in outer_degrees)
    )
    print("schedule_gate_passed=true")
    print("sampled_graph_instance_distance_certificate=false")
    print("iopp_attached=false")
    print("complete_proof_qualification=false")


if __name__ == "__main__":
    main()
