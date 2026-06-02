from nps_lab_el.crypto.lfsr import LFSR


class TestLFSR:
    def test_next_returns_16bit(self):
        lfsr = LFSR(seed=12345)
        for _ in range(100):
            val = lfsr.next()
            assert 0 <= val <= 0xFFFF

    def test_deterministic_with_same_seed(self):
        a = LFSR(seed=9999)
        b = LFSR(seed=9999)
        assert a.sequence(50) == b.sequence(50)

    def test_different_seeds_differ(self):
        a = LFSR(seed=1111)
        b = LFSR(seed=2222)
        assert a.sequence(20) != b.sequence(20)

    def test_sequence_length(self):
        lfsr = LFSR(seed=44257)
        seq = lfsr.sequence(10)
        assert len(seq) == 10

    def test_mask_value(self):
        lfsr = LFSR(seed=44257)
        masked = lfsr.mask_value(0xABCD)
        assert 0 <= masked <= 0xFFFF

    def test_correlation_score_matching_seed(self):
        seed = 44257
        lfsr = LFSR(seed)
        observed = lfsr.sequence(50)
        score = LFSR.correlation_score(observed, seed)
        assert score == 1.0

    def test_correlation_score_wrong_seed(self):
        seed = 44257
        lfsr = LFSR(seed)
        observed = lfsr.sequence(50)
        score = LFSR.correlation_score(observed, 11111)
        assert score < 1.0
