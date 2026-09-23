import math
from collections import Counter

def shannon_entropy(s: str) -> float:

    if not s:
        return 0.0

    total = len(s)
    entropy = 0.0
    for count in Counter(s).values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy

def is_high_entropy(s: str, threshold: float = 3.5, min_length: int = 20) -> bool:

    if len(s) < min_length:
        return False
    return shannon_entropy(s) >= threshold