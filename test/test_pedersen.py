import unittest
from os import urandom
from random import randint

from ethsnarks.jubjub import Point, FQ
from ethsnarks.pedersen import pedersen_hash_points, pedersen_hash_scalars, pedersen_hash_bytes, pedersen_hash_zcash_scalars, pedersen_hash_zcash_bytes


class TestPedersenHash(unittest.TestCase):
    def test_bytes(self):
        d = urandom(randint(1, 256))
        p = pedersen_hash_bytes(b'test', d)
        q = pedersen_hash_bytes(b'test', d, d)
        self.assertTrue(p.valid())
        self.assertTrue(q.valid())
        self.assertNotEqual(p, q)

    def test_points(self):
        d = urandom(10)
        p = Point.from_hash(d)
        q = pedersen_hash_points(b'test', p)
        r = pedersen_hash_points(b'test', q)
        self.assertTrue(q.valid())
        self.assertTrue(r.valid())
        self.assertNotEqual(q, r)

    def test_zcash(self):
        d = randint(1, 1024)
        p = pedersen_hash_zcash_scalars(b'test', d)
        q = pedersen_hash_zcash_scalars(b'test', d, d)
        self.assertTrue(p.valid)
        self.assertTrue(q.valid)
        self.assertNotEqual(p, q)

        self.assertEqual(
            pedersen_hash_zcash_scalars(b'test', 267),
            Point(FQ(6790798216812059804926342266703617627640027902964190490794793207272357201212),
                  FQ(2522797517250455013248440571887865304858084343310097011302610004060289809689)))

        self.assertEqual(
            pedersen_hash_zcash_scalars(b'test', 6453482891510615431577168724743356132495662554103773572771861111634748265227),
            Point(FQ(6545697115159207040330446958704617656199928059562637738348733874272425400594),
                  FQ(16414097465381367987194277536478439232201417933379523927469515207544654431390)))

        self.assertEqual(
            pedersen_hash_zcash_scalars(b'test', 21888242871839275222246405745257275088548364400416034343698204186575808495616),
            Point(FQ(16322787121012335146141962340685388833598805940095898416175167744309692564601),
                  FQ(7671892447502767424995649701270280747270481283542925053047237428072257876309)))

        self.assertEqual(
            pedersen_hash_zcash_bytes(b'test', b"abc"),
            Point(FQ(9869277320722751484529016080276887338184240285836102740267608137843906399765),
                  FQ(19790690237145851554496394080496962351633528315779989340140084430077208474328)))

        self.assertEqual(
            pedersen_hash_zcash_bytes(b'test', b"abcdefghijklmnopqrstuvwx"),
            Point(FQ(3966548799068703226441887746390766667253943354008248106643296790753369303077),
                  FQ(12849086395963202120677663823933219043387904870880733726805962981354278512988)))


if __name__ == "__main__":
    unittest.main()
