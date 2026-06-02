class LFSR:
    def __init__(self, seed: int = 44257):
        self.state = seed & 0xFFFF
        self.taps = (15, 13, 12, 10)

    def next(self) -> int:
        feedback = 0
        for tap in self.taps:
            feedback ^= (self.state >> tap) & 1
        self.state = ((self.state << 1) | feedback) & 0xFFFF
        return self.state

    def sequence(self, n: int) -> list[int]:
        return [self.next() for _ in range(n)]

    def mask_value(self, value: int) -> int:
        return value ^ self.next()

    @staticmethod
    def correlation_score(observed_seq: list[int], expected_seed: int) -> float:
        lfsr = LFSR(expected_seed)
        expected = lfsr.sequence(len(observed_seq))
        matches = sum(1 for a, b in zip(observed_seq, expected) if a == b)
        return matches / len(observed_seq) if observed_seq else 0.0
