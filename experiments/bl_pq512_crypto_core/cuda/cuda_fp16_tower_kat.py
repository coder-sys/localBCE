"""Pinned RTX KAT/runtime for Blind Ledger's frozen M31 degree-16 tower."""

import ctypes
import random
import time
from pathlib import Path

Q = 2_147_483_647

CUDA = r"""
typedef unsigned int u32;
typedef unsigned long long u64;

__device__ __forceinline__ u32 addp(u32 a, u32 b) {
    u32 s = a + b;
    return s >= 2147483647U ? s - 2147483647U : s;
}
__device__ __forceinline__ u32 subp(u32 a, u32 b) {
    return a >= b ? a - b : a + 2147483647U - b;
}
__device__ __forceinline__ u32 mulp(u32 a, u32 b) {
    u64 p = (u64)a * (u64)b;
    u64 f = (p & 2147483647ULL) + (p >> 31);
    u32 r = (u32)f;
    return r >= 2147483647U ? r - 2147483647U : r;
}

struct F2 { u32 a, b; };
struct F4 { F2 a, b; };
struct F8 { F4 a, b; };
struct F16 { F8 a, b; };

__device__ __forceinline__ F2 a2(F2 x,F2 y){return {addp(x.a,y.a),addp(x.b,y.b)};}
__device__ __forceinline__ F2 s2(F2 x,F2 y){return {subp(x.a,y.a),subp(x.b,y.b)};}
__device__ __forceinline__ F2 m2(F2 x,F2 y){
    u32 ac=mulp(x.a,y.a), bd=mulp(x.b,y.b);
    u32 cr=subp(subp(mulp(addp(x.a,x.b),addp(y.a,y.b)),ac),bd);
    return {subp(ac,bd),cr};
}
__device__ __forceinline__ F2 nr2(F2 x){
    return {subp(addp(x.a,x.a),x.b),addp(x.a,addp(x.b,x.b))};
}
__device__ __forceinline__ F4 a4(F4 x,F4 y){return {a2(x.a,y.a),a2(x.b,y.b)};}
__device__ __forceinline__ F4 s4(F4 x,F4 y){return {s2(x.a,y.a),s2(x.b,y.b)};}
__device__ __forceinline__ F4 m4(F4 x,F4 y){
    F2 ac=m2(x.a,y.a), bd=m2(x.b,y.b);
    F2 cr=s2(s2(m2(a2(x.a,x.b),a2(y.a,y.b)),ac),bd);
    return {a2(ac,nr2(bd)),cr};
}
__device__ __forceinline__ F4 nru(F4 x){return {nr2(x.b),x.a};}
__device__ __forceinline__ F8 a8(F8 x,F8 y){return {a4(x.a,y.a),a4(x.b,y.b)};}
__device__ __forceinline__ F8 s8(F8 x,F8 y){return {s4(x.a,y.a),s4(x.b,y.b)};}
__device__ __forceinline__ F8 m8(F8 x,F8 y){
    F4 ac=m4(x.a,y.a), bd=m4(x.b,y.b);
    F4 cr=s4(s4(m4(a4(x.a,x.b),a4(y.a,y.b)),ac),bd);
    return {a4(ac,nru(bd)),cr};
}
__device__ __forceinline__ F8 nrv(F8 x){return {nru(x.b),x.a};}
__device__ __forceinline__ F16 m16(F16 x,F16 y){
    F8 ac=m8(x.a,y.a), bd=m8(x.b,y.b);
    F8 cr=s8(s8(m8(a8(x.a,x.b),a8(y.a,y.b)),ac),bd);
    return {a8(ac,nrv(bd)),cr};
}
__device__ __forceinline__ F2 l2(const u32* p){return {p[0],p[1]};}
__device__ __forceinline__ F4 l4(const u32* p){return {l2(p),l2(p+2)};}
__device__ __forceinline__ F8 l8(const u32* p){return {l4(p),l4(p+4)};}
__device__ __forceinline__ F16 l16(const u32* p){return {l8(p),l8(p+8)};}
__device__ __forceinline__ void st2(u32* p,F2 x){p[0]=x.a;p[1]=x.b;}
__device__ __forceinline__ void st4(u32* p,F4 x){st2(p,x.a);st2(p+2,x.b);}
__device__ __forceinline__ void st8(u32* p,F8 x){st4(p,x.a);st4(p+4,x.b);}
__device__ __forceinline__ void st16(u32* p,F16 x){st8(p,x.a);st8(p+8,x.b);}

extern "C" __global__ void fp16_mul(const u32* left,const u32* right,u32* out,u64 count){
    u64 i=(u64)blockIdx.x*blockDim.x+threadIdx.x;
    if(i<count) st16(out+16*i,m16(l16(left+16*i),l16(right+16*i)));
}
"""


def ck(code, name):
    if code:
        raise RuntimeError(f"{name}:{code}")


def p_add(x, y):
    z = x + y
    return z - Q if z >= Q else z


def p_sub(x, y):
    return x - y if x >= y else x + Q - y


def p_mul(x, y):
    z = x * y
    z = (z & Q) + (z >> 31)
    return z - Q if z >= Q else z


def add(x, y):
    return tuple(p_add(a, b) for a, b in zip(x, y))


def sub(x, y):
    return tuple(p_sub(a, b) for a, b in zip(x, y))


def mul2(x, y):
    ac, bd = p_mul(x[0], y[0]), p_mul(x[1], y[1])
    cross = p_sub(p_sub(p_mul(p_add(x[0], x[1]), p_add(y[0], y[1])), ac), bd)
    return p_sub(ac, bd), cross


def nr2(x):
    return p_sub(p_add(x[0], x[0]), x[1]), p_add(x[0], p_add(x[1], x[1]))


def tower_mul(x, y, lower_mul, nonresidue):
    n = len(x) // 2
    xa, xb, ya, yb = x[:n], x[n:], y[:n], y[n:]
    ac, bd = lower_mul(xa, ya), lower_mul(xb, yb)
    cross = sub(sub(lower_mul(add(xa, xb), add(ya, yb)), ac), bd)
    return add(ac, nonresidue(bd)) + cross


def mul4(x, y):
    return tower_mul(x, y, mul2, nr2)


def nru(x):
    return nr2(x[2:]) + x[:2]


def mul8(x, y):
    return tower_mul(x, y, mul4, nru)


def nrv(x):
    return nru(x[4:]) + x[:4]


def mul16(x, y):
    return tower_mul(x, y, mul8, nrv)


class Runtime:
    def __init__(self, nvrtc_dir):
        ctypes.windll.kernel32.SetDllDirectoryW(str(nvrtc_dir))
        self.nvrtc = ctypes.WinDLL(str(nvrtc_dir / "nvrtc64_120_0.dll"))
        self.cuda = ctypes.WinDLL("nvcuda.dll")
        self._bind()
        ck(self.cuda.cuInit(0), "cuInit")
        dev = ctypes.c_int()
        ck(self.cuda.cuDeviceGet(ctypes.byref(dev), 0), "cuDeviceGet")
        self.ctx = ctypes.c_void_p()
        ck(self.cuda.cuCtxCreate_v2(ctypes.byref(self.ctx), 0, dev), "cuCtxCreate")
        self.allocs = []
        self.modules = []

    def _bind(self):
        n, c = self.nvrtc, self.cuda
        n.nvrtcCreateProgram.argtypes = [ctypes.POINTER(ctypes.c_void_p),ctypes.c_char_p,ctypes.c_char_p,ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p]
        n.nvrtcCompileProgram.argtypes = [ctypes.c_void_p,ctypes.c_int,ctypes.POINTER(ctypes.c_char_p)]
        n.nvrtcGetPTXSize.argtypes = [ctypes.c_void_p,ctypes.POINTER(ctypes.c_size_t)]
        n.nvrtcGetPTX.argtypes = [ctypes.c_void_p,ctypes.c_char_p]
        n.nvrtcDestroyProgram.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        c.cuInit.argtypes=[ctypes.c_uint]
        c.cuDeviceGet.argtypes=[ctypes.POINTER(ctypes.c_int),ctypes.c_int]
        c.cuCtxCreate_v2.argtypes=[ctypes.POINTER(ctypes.c_void_p),ctypes.c_uint,ctypes.c_int]
        c.cuModuleLoadData.argtypes=[ctypes.POINTER(ctypes.c_void_p),ctypes.c_void_p]
        c.cuModuleGetFunction.argtypes=[ctypes.POINTER(ctypes.c_void_p),ctypes.c_void_p,ctypes.c_char_p]
        c.cuMemAlloc_v2.argtypes=[ctypes.POINTER(ctypes.c_uint64),ctypes.c_size_t]
        c.cuMemcpyHtoD_v2.argtypes=[ctypes.c_uint64,ctypes.c_void_p,ctypes.c_size_t]
        c.cuMemcpyDtoH_v2.argtypes=[ctypes.c_void_p,ctypes.c_uint64,ctypes.c_size_t]
        c.cuLaunchKernel.argtypes=[ctypes.c_void_p,ctypes.c_uint,ctypes.c_uint,ctypes.c_uint,ctypes.c_uint,ctypes.c_uint,ctypes.c_uint,ctypes.c_uint,ctypes.c_void_p,ctypes.POINTER(ctypes.c_void_p),ctypes.c_void_p]
        c.cuCtxSynchronize.argtypes=[]
        c.cuMemFree_v2.argtypes=[ctypes.c_uint64]
        c.cuModuleUnload.argtypes=[ctypes.c_void_p]
        c.cuCtxDestroy_v2.argtypes=[ctypes.c_void_p]

    def compile_ptx(self, source):
        prog = ctypes.c_void_p()
        ck(self.nvrtc.nvrtcCreateProgram(ctypes.byref(prog),source.encode(),b"fp16.cu",0,None,None),"create")
        opts=(ctypes.c_char_p*2)(b"--gpu-architecture=compute_89",b"--std=c++17")
        ck(self.nvrtc.nvrtcCompileProgram(prog,2,opts),"compile")
        size=ctypes.c_size_t()
        ck(self.nvrtc.nvrtcGetPTXSize(prog,ctypes.byref(size)),"ptx_size")
        ptx=ctypes.create_string_buffer(size.value)
        ck(self.nvrtc.nvrtcGetPTX(prog,ptx),"ptx")
        ck(self.nvrtc.nvrtcDestroyProgram(ctypes.byref(prog)),"destroy_program")
        return ptx.raw

    def load_module(self, module_image):
        if not module_image or not (
            module_image[:4] == b"\x7fELF"
            or module_image[-1] == 0
        ):
            raise ValueError("noncanonical_cuda_module")
        image=(ctypes.c_char*len(module_image)).from_buffer_copy(module_image)
        module=ctypes.c_void_p()
        ck(self.cuda.cuModuleLoadData(ctypes.byref(module),ctypes.cast(image,ctypes.c_void_p)),"module")
        self.modules.append(module)
        return module

    def compile_module(self, source):
        return self.load_module(self.compile_ptx(source))

    def module_function(self, module, function):
        result=ctypes.c_void_p()
        ck(self.cuda.cuModuleGetFunction(ctypes.byref(result),module,function),"function")
        return result

    def compile(self, source=CUDA, function=b"fp16_mul"):
        self.module=self.compile_module(source)
        self.fn=ctypes.c_void_p()
        ck(self.cuda.cuModuleGetFunction(ctypes.byref(self.fn),self.module,function),"function")

    def alloc(self, size):
        p=ctypes.c_uint64()
        ck(self.cuda.cuMemAlloc_v2(ctypes.byref(p),size),"alloc")
        self.allocs.append(p.value)
        return p.value

    def close(self):
        for p in reversed(self.allocs):
            ck(self.cuda.cuMemFree_v2(p),"free")
        for module in reversed(self.modules):
            ck(self.cuda.cuModuleUnload(module),"unload")
        ck(self.cuda.cuCtxDestroy_v2(self.ctx),"destroy_context")


def main():
    nvrtc = Path(__file__).parent / "cuda_nvrtc" / "nvidia" / "cuda_nvrtc" / "bin"
    count = 262_144
    kat = 4_097
    rng = random.Random(0xB11D1ED6E)
    words = count * 16
    host_type = ctypes.c_uint32 * words
    left = host_type(*(rng.randrange(Q) for _ in range(words)))
    right = host_type(*(rng.randrange(Q) for _ in range(words)))
    output = host_type()
    rt = Runtime(nvrtc)
    try:
        start = time.perf_counter()
        rt.compile()
        compile_seconds = time.perf_counter() - start
        size = ctypes.sizeof(left)
        dl, dr, do = rt.alloc(size), rt.alloc(size), rt.alloc(size)
        ck(rt.cuda.cuMemcpyHtoD_v2(dl,ctypes.cast(left,ctypes.c_void_p),size),"copy_left")
        ck(rt.cuda.cuMemcpyHtoD_v2(dr,ctypes.cast(right,ctypes.c_void_p),size),"copy_right")
        ca, cb, co, cn = ctypes.c_uint64(dl),ctypes.c_uint64(dr),ctypes.c_uint64(do),ctypes.c_uint64(count)
        args=(ctypes.c_void_p*4)(ctypes.cast(ctypes.byref(ca),ctypes.c_void_p),ctypes.cast(ctypes.byref(cb),ctypes.c_void_p),ctypes.cast(ctypes.byref(co),ctypes.c_void_p),ctypes.cast(ctypes.byref(cn),ctypes.c_void_p))
        ck(rt.cuda.cuLaunchKernel(rt.fn,(count+255)//256,1,1,256,1,1,0,None,args,None),"warmup")
        ck(rt.cuda.cuCtxSynchronize(),"warmup_sync")
        times=[]
        for _ in range(5):
            start=time.perf_counter()
            ck(rt.cuda.cuLaunchKernel(rt.fn,(count+255)//256,1,1,256,1,1,0,None,args,None),"launch")
            ck(rt.cuda.cuCtxSynchronize(),"sync")
            times.append(time.perf_counter()-start)
        ck(rt.cuda.cuMemcpyDtoH_v2(ctypes.cast(output,ctypes.c_void_p),do,size),"copy_output")
        for index in range(kat):
            expected=mul16(tuple(left[16*index:16*index+16]),tuple(right[16*index:16*index+16]))
            actual=tuple(output[16*index:16*index+16])
            if actual != expected:
                raise SystemExit(f"mismatch_at={index}\nexpected={expected}\nactual={actual}")
        times.sort()
        median=times[len(times)//2]
        print(f"kat_pairs={kat}")
        print("kat_match=true")
        print(f"batch_pairs={count}")
        print(f"nvrtc_compile_seconds={compile_seconds:.6f}")
        print(f"kernel_median_seconds={median:.9f}")
        print(f"fp16_multiplications_per_second={count/median:.3f}")
        print(f"device_bytes={3*size}")
    finally:
        rt.close()


if __name__ == "__main__":
    main()
