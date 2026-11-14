"""Generate a lane-complemented unrolled Keccak-f for Lean and check it in Python against hashlib."""
import hashlib, random, sys, itertools

M = (1 << 64) - 1
# pi/rho table copied from Sha3Fast.round: (dst b index, src a index, column of d, rotation)
TAB = [(0,0,0,0),(16,5,0,36),(7,10,0,3),(23,15,0,41),(14,20,0,18),
       (10,1,1,1),(1,6,1,44),(17,11,1,10),(8,16,1,45),(24,21,1,2),
       (20,2,2,62),(11,7,2,6),(2,12,2,43),(18,17,2,15),(9,22,2,61),
       (5,3,3,28),(21,8,3,55),(12,13,3,25),(3,18,3,21),(19,23,3,56),
       (15,4,4,27),(6,9,4,20),(22,14,4,39),(13,19,4,8),(4,24,4,14)]
RC = [0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,0x000000000000808B,0x0000000080000001,
      0x8000000080008081,0x8000000000008009,0x000000000000008A,0x0000000000000088,0x0000000080008009,0x000000008000000A,
      0x000000008000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,0x8000000000008002,0x8000000000000080,
      0x000000000000800A,0x800000008000000A,0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008]

def round_ops(pin, pout, rc, tag):
    """Return (ops, notcount). ops: list of (dst, expr). Inputs a0..a24 (stored, flags pin); outputs named via tag.
    Output lane k stored with flag pout[k]."""
    ops = []; nots = 0
    def v(n): return n
    cf = [pin[x]^pin[x+5]^pin[x+10]^pin[x+15]^pin[x+20] for x in range(5)]
    for x in range(5):
        ops.append((f"c{x}", ('xor', [f"a{x+5*y}" for y in range(5)])))
    for x in range(5):
        ops.append((f"d{x}", ('xor', [f"c{(x+4)%5}", ('rl', f"c{(x+1)%5}", 1)])))
    df = [cf[(x+4)%5]^cf[(x+1)%5] for x in range(5)]
    bf = {}
    for (dst, src, col, rot) in TAB:
        t = ('xor', [f"a{src}", f"d{col}"])
        ops.append((f"b{dst}", ('rl', t, rot) if rot else t))
        bf[dst] = pin[src] ^ df[col]
    for r in range(5):
        for i in range(5):
            k = 5*r+i
            j1, j2 = 5*r+(i+1)%5, 5*r+(i+2)%5
            x0, x1, x2 = f"b{k}", f"b{j1}", f"b{j2}"
            p1, p2 = bf[j1], bf[j2]
            # g and its complement offset c relative to f = ~a1 & a2
            if (p1,p2) == (0,1): g, c, cost = ('or', x1, x2), 1, 0
            elif (p1,p2) == (1,0): g, c, cost = ('and', x1, x2), 0, 0
            elif (p1,p2) == (0,0): g, c, cost = ('and', ('not', x1), x2), 0, 1
            else: g, c, cost = ('and', x1, ('not', x2)), 0, 1
            flag = bf[k] ^ c
            e = ('xor', [x0, g] + ([f"RC"] if k == 0 and rc is not None else []))
            if flag != pout[k]:
                e = ('not', e); cost += 1
            nots += cost
            ops.append((f"{tag}{k}", e))
    return ops, nots

def best_p(trials=200000, seed=1):
    rnd = random.Random(seed)
    best = None
    def cost(p):
        _, n = round_ops(p, p, None, "o")
        return n
    for start in range(trials):
        p = [rnd.randint(0,1) for _ in range(25)] if start else [1 if i in (1,2,8,12,17,20) else 0 for i in range(25)]
        c = cost(p)
        improved = True
        while improved:
            improved = False
            for i in range(25):
                p[i] ^= 1
                c2 = cost(p)
                if c2 < c: c = c2; improved = True
                else: p[i] ^= 1
        if best is None or c < best[0]: best = (c, p[:]);
        if start > 300: break
    return best

# ---------- evaluation
def rol(x, n): return ((x << n) | (x >> (64 - n))) & M if n else x
def ev(e, env):
    if isinstance(e, str):
        return RC_VAL if e == "RC" else env[e]
    op = e[0]
    if op == 'xor':
        r = 0
        for t in e[1]: r ^= ev(t, env)
        return r
    if op == 'rl': return rol(ev(e[1], env), e[2])
    if op == 'and': return ev(e[1], env) & ev(e[2], env)
    if op == 'or': return ev(e[1], env) | ev(e[2], env)
    if op == 'not': return ev(e[1], env) ^ M
RC_VAL = 0

def run_round(ops, a, rc):
    global RC_VAL
    RC_VAL = rc
    env = {f"a{i}": a[i] for i in range(25)}
    for dst, e in ops: env[dst] = ev(e, env)
    return [env[f"o{k}"] for k in range(25)]

def sponge_py(perm, p, rate, suffix, data, n):
    mask = [(M if p[i] else 0) for i in range(25)]
    st = mask[:]  # stored zero state
    pad = bytearray(data) + bytes([suffix]);
    while len(pad) % rate: pad.append(0)
    pad[-1] |= 0x80
    for off in range(0, len(pad), rate):
        for l in range(rate//8): st[l] ^= int.from_bytes(pad[off+8*l:off+8*l+8], 'little')
        st = perm(st)
    out = b""
    while True:
        out += b"".join(((st[l]^mask[l]).to_bytes(8,'little')) for l in range(rate//8))
        if len(out) >= n: return out[:n]
        st = perm(st)

def check(p):
    ops, nots = round_ops(p, p, 0, "o")
    def perm(st):
        for r in range(24): st = run_round(ops, st, RC[r])
        return st
    rnd = random.Random(5)
    for ln in (0, 1, 31, 64, 71, 72, 73, 135, 136, 137, 400):
        d = rnd.randbytes(ln)
        assert sponge_py(perm, p, 136, 0x06, d, 32) == hashlib.sha3_256(d).digest(), ln
        assert sponge_py(perm, p, 72, 0x06, d, 64) == hashlib.sha3_512(d).digest(), ln
        assert sponge_py(perm, p, 168, 0x1f, d, 200) == hashlib.shake_128(d).digest(200), ln
    return nots

def rend(e, lean=True):
    if isinstance(e, str): return e
    op = e[0]
    if op == 'xor': return "(" + " ^^^ ".join(rend(t) for t in e[1]) + ")"
    if op == 'rl': return f"rl {rend(e[1])} {e[2]}"
    if op == 'and': return f"({rend(e[1])} &&& {rend(e[2])})"
    if op == 'or': return f"({rend(e[1])} ||| {rend(e[2])})"
    if op == 'not': return f"(~~~{rend(e[1])})"

if __name__ == "__main__":
    base = [0]*25
    print("plain not count", round_ops(base, base, 0, "o")[1])
    kcp = [1 if i in (1,2,8,12,17,20) else 0 for i in range(25)]
    print("kcp cost", round_ops(kcp, kcp, 0, "o")[1])
    c, p = best_p()
    print("best", c, [i for i in range(25) if p[i]])
    print("check", check(p))

import re, io
def emit_perm(p, R, indent="    "):
    T = 24 // R
    args = " ".join(f"a{i}" for i in range(25))
    lines = []
    cur = [f"a{i}" for i in range(25)]
    for r in range(R):
        ops, _ = round_ops(p, p, 0, "o")
        def nm(n):
            if re.fullmatch(r"a\d+", n): return cur[int(n[1:])]
            return f"{n}_{r}"
        def rd(e):
            if isinstance(e, str):
                if e == "RC":
                    return f"(rcs[{R}*({T}-(n+1))+{r}]!)" if T > 1 else f"0x{RC[r]:016X}"
                return nm(e)
            op = e[0]
            if op == 'xor': return "(" + " ^^^ ".join(rd(t) for t in e[1]) + ")"
            if op == 'rl': return f"(rl {rd(e[1])} {e[2]})"
            if op == 'and': return f"({rd(e[1])} &&& {rd(e[2])})"
            if op == 'or': return f"({rd(e[1])} ||| {rd(e[2])})"
            if op == 'not': return f"(~~~{rd(e[1])})"
        for dst, e in plane_order(ops):
            lines.append(f"{indent}let {dst}_{r} := {rd(e)}")
        cur = [f"o{k}_{r}" for k in range(25)]
    return lines, cur

def plane_order(ops):
    """Theta first, then each output plane: its five rho-pi lanes, then its five chi lanes.  Only one plane's lanes are
    live at a time, so the compiled loop spills less than in source-lane order (about 10% faster on x86-64)."""
    od = {dst: (dst, e) for dst, e in ops}
    return [od[f"{v}{x}"] for v in "cd" for x in range(5)] + [od[f"{v}{5 * y + i}"] for y in range(5) for v in "bo" for i in range(5)]

def perm_text(p, R):
    T = 24 // R
    args = " ".join(f"a{i}" for i in range(25))
    lines, cur = emit_perm(p, R, "    ")
    out = []
    ret = "⟨" + ", ".join(f"a{i}" for i in range(25)) + "⟩"
    if T == 1:
        out.append(f"def perm (_n : Nat) ({' '.join('a'+str(i) for i in range(25))} : UInt64) : St :=")
        out += [l[2:] for l in lines]
        out.append("  ⟨" + ", ".join(cur) + "⟩")
    else:
        out.append(f"def perm : (n : Nat) → ({args} : UInt64) → St")
        out.append(f"  | 0, {', '.join('a'+str(i) for i in range(25))} => {ret}")
        out.append(f"  | n + 1, {', '.join('a'+str(i) for i in range(25))} =>")
        out += lines
        out.append("    perm n " + " ".join(cur))
    out.append("\n/-- Loop steps for one full permutation. -/\ndef permSteps : Nat := %d" % T)
    return "\n".join(out) + "\n"

def patch(path, R):
    c, p = best_p()
    s = io.open(path, encoding='utf-8', newline='').read()
    a = s.index("/-- Keccak-f[1600]"); b = s.index("def keccakF")
    hdr = ("/-- Keccak-f[1600] with six lanes held complemented (lanes " + ", ".join(str(i) for i in range(25) if p[i]) +
           "), which removes most of the NOT steps of chi: a stored lane is the true lane xor `flip` (all ones for those six).\n"
           f"    {R} rounds are written out per loop step, each in plane order (`plane_order`). -/\n")
    s = s[:a] + hdr + perm_text(p, R) + "\n" + s[b:]
    io.open(path, 'w', encoding='utf-8', newline='').write(s)
    return p
