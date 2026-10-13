"""Experimental stable-version subset; not a complete npm resolver or runtime code."""
import re

NUMBER = r"(0|[1-9][0-9]*)"
STABLE = re.compile(rf"{NUMBER}\.{NUMBER}\.{NUMBER}", re.ASCII)
# Reserve one increment for npm's exclusive upper-bound expansion.
MAX_COMPONENT = 2**53 - 2


def parse(value):
    if not isinstance(value, str) or len(value) > 256:
        return None
    match = STABLE.fullmatch(value)
    if not match:
        return None
    parts = tuple(map(int, match.groups()))
    return parts if max(parts) <= MAX_COMPONENT else None


def satisfies(version, spec):
    """Exact, ~x.y.z and ^x.y.z only; unsupported returns None/UNKNOWN."""
    actual = parse(version)
    if actual is None or not isinstance(spec, str):
        return None
    operator = spec[:1] if spec[:1] in ("~", "^") else ""
    minimum = parse(spec[len(operator):])
    if minimum is None:
        return None
    if not operator:
        return actual == minimum
    if operator == "~":
        return actual[:2] == minimum[:2] and actual >= minimum
    # Caret permits changes to the right of the first nonzero coordinate.
    pivot = next((i for i, part in enumerate(minimum) if part), 2)
    return actual[:pivot + 1] == minimum[:pivot + 1] and actual >= minimum
