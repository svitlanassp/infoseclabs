import unittest

from lab2.lab2 import MyMD5


class TestMyMD5(unittest.TestCase):
    def setUp(self):
        self.md5 = MyMD5()

    def test_rfc_examples(self):
        tests = [
            ("", "d41d8cd98f00b204e9800998ecf8427e"),
            ("a", "0cc175b9c0f1b6a831c399e269772661"),
            ("abc", "900150983cd24fb0d6963f7d28e17f72"),
            ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            ("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"),
            ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
             "d174ab98d277d9f5a5611c2c9f419d9f"),
            ("12345678901234567890123456789012345678901234567890123456789012345678901234567890",
             "57edf4a22be3c955ac49da2e2107b67a")
        ]

        for text, expected in tests:
                result = MyMD5.hash_string(text)
                self.assertEqual(result.lower(), expected.lower())

    def test_left_rotate(self):
        tests = [
            (0x12345678, 4, 0x23456781),
            (0x00000001, 1, 0x00000002),
            (0x80000000, 1, 0x00000001),
            (0xFFFFFFFF, 8, 0xFFFFFFFF),
        ]
        for x, n, expected in tests:
            self.assertEqual(self.md5.left_rotate(x, n), expected)

    def test_buffer(self):
        text = "Test message for partial updates"

        hash1 = MyMD5.hash_string(text)

        md5 = MyMD5()
        parts = [text[i:i + 5] for i in range(0, len(text), 5)]
        for part in parts:
            md5.update(part.encode('utf-8'))

        self.assertEqual(hash1, md5.digest())



if __name__ == "__main__":
    unittest.main()