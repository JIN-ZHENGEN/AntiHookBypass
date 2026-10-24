import struct
d=open('hdex/classes.dex','rb').read()
def u4(o): return struct.unpack('<I',d[o:o+4])[0]
def u2(o): return struct.unpack('<H',d[o:o+2])[0]
string_ids_size=u4(0x38); string_ids_off=u4(0x3c)
type_ids_off=u4(0x44); method_ids_off=u4(0x5c)
class_defs_size=u4(0x60); class_defs_off=u4(0x64)
def get_string(i):
    o=u4(string_ids_off+4*i); p=o
    while d[p]&0x80: p+=1
    p+=1
    end=d.index(b'\0',p)
    return d[p:end].decode('utf-8','replace')
strings=[get_string(i) for i in range(string_ids_size)]
keys=['FIND XPOSED API','anti xposed','Find Lsposed Hook Module','ChooseUtils.choose']
idxs={i for i,s in enumerate(strings) if any(k in s for k in keys)}
print("命中 string idx:",idxs)
for i in idxs: print("   ",i,repr(strings[i][:60]))
def type_name(ti): return strings[u4(type_ids_off+4*ti)]
def method_info(mi):
    b=method_ids_off+8*mi
    return type_name(u2(b)), strings[u4(b+4)]
class Uleb:
    def __init__(self,data,pos): self.d=data; self.p=pos
    def read(self):
        shift=0;val=0
        while True:
            x=self.d[self.p]; self.p+=1
            val|=(x&0x7f)<<shift
            if not x&0x80: return val
            shift+=7
hits=set()
for ci in range(class_defs_size):
    b=class_defs_off+ci*32
    cname=type_name(u4(b)); data_off=u4(b+24)
    if data_off==0: continue
    u=Uleb(d,data_off)
    sf=u.read(); inf=u.read(); dm=u.read(); vm=u.read()
    for _ in range(sf+inf):
        u.read(); u.read()
    for _ in range(dm+vm):
        mid=u.read(); acc=u.read(); code=u.read()
        if code==0: continue
        insns_size=u4(code+12); base=code+16
        for k in range(0,insns_size*2,2):
            w=u2(base+k); op=w&0xff
            if op in (0x1a,0x1b):
                idx=u2(base+k+2)
                if idx in idxs:
                    cn,mn=method_info(mid)
                    hits.add((cn,mn))
                    break
print("\n引用方法:")
for cn,mn in sorted(hits): print("  ",cn,"->",mn)
