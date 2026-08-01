"""High-precision Hint-MLWE geometry and encoded-size derivation."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, ROUND_CEILING, localcontext


PI = Decimal(
    "3.141592653589793238462643383279502884197169399375105820974944"
    "5923078164062862089986280348253421170679"
)
LN2 = Decimal(
    "0.693147180559945309417232121458176568075500134360255254120680"
    "0094933936219696947156058633269964186875"
)


def _ceil(value: Decimal) -> int:
    return int(value.to_integral_value(rounding=ROUND_CEILING))


def _log2(value: Decimal) -> Decimal:
    if value <= 0:
        raise ValueError("log2_input_must_be_positive")
    return value.ln() / LN2


def smoothing_parameter_bound(
    dimension: int, scale: Decimal, epsilon_bits: int
) -> int:
    if type(dimension) is not int or dimension <= 0:
        raise ValueError("dimension_must_be_positive_integer")
    if type(epsilon_bits) is not int or epsilon_bits <= 0:
        raise ValueError("epsilon_bits_must_be_positive_integer")
    if scale <= 0:
        raise ValueError("scale_must_be_positive")
    with localcontext() as context:
        context.prec = 120
        epsilon = Decimal(2) ** -epsilon_bits
        inside = (
            Decimal(2)
            * Decimal(dimension)
            * (Decimal(1) + Decimal(1) / epsilon)
        )
        return _ceil((inside.ln() / PI).sqrt() * scale)


@dataclass(frozen=True, slots=True)
class GeometryInput:
    degree: int
    omega: int
    eta: int
    epsilon_bits: int
    base: int
    modulus: int
    dropped_bits: int
    compression_gamma: int
    message_rank: int
    extension_rank: int
    mlwe_rank: int
    msis_rank: int
    gadget_rank: int = 2


@dataclass(frozen=True, slots=True)
class GeometryResult:
    input: GeometryInput
    randomness_rank: int
    sigma1: int
    sigma2: int
    simulation_sigma: int
    frak_s1_squared_ceiling: int
    frak_s2_squared_ceiling: int
    binding_bound_ceiling: int
    knowledge_bound_ceiling: int
    binding_below_modulus: bool
    knowledge_below_modulus: bool
    compression_divides_modulus_minus_one: bool
    compression_inequality_holds: bool
    proof_bytes_ceiling: int
    proof_kib: str
    matrix_coefficients: int
    modulus_limbs_64: int


def derive_geometry(parameters: GeometryInput) -> GeometryResult:
    with localcontext() as context:
        context.prec = 120
        d = parameters.degree
        eta = Decimal(parameters.eta)
        b = Decimal(parameters.base)
        p = parameters.modulus
        k = parameters.gadget_rank
        m1 = parameters.message_rank
        kmlwe = parameters.mlwe_rank
        kmsis = parameters.msis_rank
        m2 = kmlwe + kmsis + parameters.extension_rank
        epsilon_bits = parameters.epsilon_bits
        sqrt2 = Decimal(2).sqrt()
        sqrt_p = Decimal(p).sqrt()

        sigma1 = smoothing_parameter_bound(
            k * m1 * d, Decimal(1), epsilon_bits
        )
        frak_s1 = max(
            Decimal(
                smoothing_parameter_bound(
                    k * m1 * d, Decimal(1), epsilon_bits
                )
            )
            / sqrt2,
            sqrt2
            / (b - 1)
            * Decimal(
                smoothing_parameter_bound(
                    m1 * d, sqrt_p, epsilon_bits
                )
            ),
        )

        def varsigma1() -> int:
            inverse = (
                Decimal(1) / Decimal(sigma1 * sigma1)
                + eta * eta / (Decimal(2) * frak_s1 * frak_s1)
            )
            return _ceil((Decimal("0.5") / inverse).sqrt())

        ideal_s1_floor = smoothing_parameter_bound(
            k * m1 * d, sqrt_p, epsilon_bits
        )
        while (
            sqrt2 * (b - 1) * Decimal(varsigma1())
            < Decimal(ideal_s1_floor)
        ):
            frak_s1 *= sqrt2

        base_smoothing = smoothing_parameter_bound(
            kmlwe * d, Decimal(1), epsilon_bits
        )
        sigma2 = 2 * base_smoothing
        frak_s2 = sqrt2 * Decimal(base_smoothing)

        def varsigma2() -> int:
            inverse = (
                Decimal(1) / Decimal(sigma2 * sigma2)
                + eta * eta / (frak_s2 * frak_s2)
            )
            return _ceil((Decimal("0.5") / inverse).sqrt())

        while Decimal(varsigma2()) < sqrt2 * Decimal(base_smoothing):
            frak_s2 *= sqrt2

        alpha1 = (
            (b + 1)
            * Decimal(sigma1)
            * Decimal(k * m1 * d).sqrt()
        )
        alpha2 = (
            (b + 1)
            * Decimal(sigma2)
            * Decimal(m2 * d).sqrt()
        )
        beta1 = (
            (b + 1)
            * (eta * Decimal(sigma1) + sqrt2 * frak_s1)
            * Decimal(k * m1 * d).sqrt()
        )
        beta2 = (
            (eta * Decimal(sigma2) + frak_s2)
            * Decimal(m2 * d).sqrt()
            + eta
            * (Decimal(2) ** (parameters.dropped_bits - 1))
            * Decimal(kmsis * d).sqrt()
            + Decimal(parameters.compression_gamma)
            * Decimal(kmsis * d).sqrt()
            / Decimal(2)
        )
        binding = Decimal(2) * (alpha1 * alpha1 + alpha2 * alpha2).sqrt()
        knowledge = (
            Decimal(8)
            * eta
            * (beta1 * beta1 + beta2 * beta2).sqrt()
        )

        logp = p.bit_length()
        full_size_bits = (
            kmsis * d * (logp - parameters.dropped_bits)
            + parameters.extension_rank * d * logp
        )
        hint_bits = Decimal("2.25") * Decimal(kmsis * d)
        challenge_bits = (2 * parameters.omega + 1).bit_length() * d
        z1_coefficient_bits = Decimal(
            _ceil(
                _log2(
                    eta * (b + 1) * Decimal(sigma1)
                    + sqrt2 * frak_s1
                )
            )
        ) + Decimal("2.57")
        z2_coefficient_bits = Decimal(
            _ceil(
                _log2(eta * Decimal(sigma2) + frak_s2)
            )
        ) + Decimal("2.57")
        z1_bits = Decimal(k * m1 * d) * z1_coefficient_bits
        z2_bits = Decimal(m2 * d) * z2_coefficient_bits
        proof_bits = (
            Decimal(full_size_bits + challenge_bits)
            + hint_bits
            + z1_bits
            + z2_bits
        )
        proof_bytes = _ceil(proof_bits / Decimal(8))
        proof_kib = str(
            (Decimal(proof_bytes) / Decimal(1024)).quantize(
                Decimal("0.01")
            )
        )

        gamma = parameters.compression_gamma
        compression_inequality = (
            Decimal(2) ** (parameters.dropped_bits - 1)
            * Decimal(parameters.omega * d)
            < Decimal(gamma)
        )
        matrix_coefficients = (
            kmsis * (k * m1 + m2) * d
        )
        return GeometryResult(
            input=parameters,
            randomness_rank=m2,
            sigma1=sigma1,
            sigma2=sigma2,
            simulation_sigma=varsigma2(),
            frak_s1_squared_ceiling=_ceil(frak_s1 * frak_s1),
            frak_s2_squared_ceiling=_ceil(frak_s2 * frak_s2),
            binding_bound_ceiling=_ceil(binding),
            knowledge_bound_ceiling=_ceil(knowledge),
            binding_below_modulus=binding < Decimal(p),
            knowledge_below_modulus=knowledge < Decimal(p),
            compression_divides_modulus_minus_one=(
                gamma > 0 and (p - 1) % gamma == 0
            ),
            compression_inequality_holds=compression_inequality,
            proof_bytes_ceiling=proof_bytes,
            proof_kib=proof_kib,
            matrix_coefficients=matrix_coefficients,
            modulus_limbs_64=(p.bit_length() + 63) // 64,
        )


PUBLISHED_SET1 = GeometryInput(
    degree=64,
    omega=8,
    eta=140,
    epsilon_bits=128,
    base=1_073_741_874,
    modulus=1_152_921_611_981_031_877,
    dropped_bits=32,
    compression_gamma=2_111_110_197_156,
    message_rank=12,
    extension_rank=2,
    mlwe_rank=34,
    msis_rank=33,
)

D256_BOX4_Q68_K29 = GeometryInput(
    degree=256,
    omega=4,
    eta=1_020,
    epsilon_bits=397,
    base=19_500_000_010,
    modulus=380_250_000_390_000_000_101,
    dropped_bits=0,
    compression_gamma=2_498,
    message_rank=12,
    extension_rank=2,
    mlwe_rank=29,
    msis_rank=33,
)
