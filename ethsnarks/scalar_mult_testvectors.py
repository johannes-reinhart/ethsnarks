import random

from ethsnarks.jubjub import Point


def generate_scalar_mult_testvectors():
    ps = []
    ss = []
    ms = []

    p1 = Point(17777552123799933955779906779655732241715742912184938656739573121738514868268,
                         2626589144620713026669568689430873010625803728049924121243784502389097019475)
    s1 = 6453482891510615431577168724743356132495662554103773572771861111634748265227
    m = p1.mult(s1)

    ps.append(p1)
    ss.append(s1)
    ms.append(m)

    s1 = 53482891510615431577168724743356132495662554103773572771861111634748265227
    m = p1.mult(s1)

    ps.append(p1)
    ss.append(s1)
    ms.append(m)

    for i in range(5):
        #p = Point.random()
        p = p1
        s = random.randrange(2**251)
        m = p.mult(s)

        ps.append(p)
        ss.append(s)
        ms.append(m)

    for p, s, m in zip(ps, ss, ms):
        print(f"------------")
        print(f"s: {s}\npx: {p.x}\npy: {p.y}\n(s*p)x: {m.x}\n(s*p)y: {m.y}\n")


if __name__ == '__main__':
    generate_scalar_mult_testvectors()