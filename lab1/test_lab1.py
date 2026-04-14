import unittest
from lab1.lab1 import generator, gcd, cesaro, period

class TestGenerator(unittest.TestCase):
    def test_gcd(self):
        self.assertEqual(gcd(48, 18), 6)
        self.assertEqual(gcd(101, 103), 1)
        self.assertEqual(gcd(0, 5), 5)
        self.assertEqual(gcd(7, 0), 7)

    def test_generator_sequence(self):
        result = generator(10, 3, 1, 2, 2)
        self.assertEqual(result, [7, 2])

    def test_period_simple(self):
        p = period(10, 3, 1, 2)
        self.assertEqual(p, 2)

    def test_cesaro_coprime(self):
        nums = [2, 3, 5, 7, 2, 4]
        self.assertEqual(cesaro(nums), 3)

    def test_cesaro_no_coprime(self):
        nums = [2, 4, 6, 8]
        self.assertEqual(cesaro(nums), 0)

    def test_cesaro_empty_or_small(self):
        self.assertEqual(cesaro([]), 0)
        self.assertEqual(cesaro([1]), 0)

    def test_generator_length(self):
        n = 100
        nums = generator(268435455, 3375, 4181, 19, n)
        self.assertEqual(len(nums), n)

    def test_range(self):
        nums = generator(9, 2, 1, 1, 100)
        self.assertTrue(all(0 <= x < 9 for x in nums))

    def test_variant_parameters(self):
        m = 268435455
        a = 3375
        c = 4181
        x0 = 19
        nums = generator(m, a, c, x0, 10)
        self.assertEqual(len(nums), 10)
        self.assertEqual(nums[0], 68306)

if __name__ == '__main__':
    unittest.main()