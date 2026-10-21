"""Deterministic, bounded pack/idx fixture; no VCS engine in production."""
import hashlib
import struct
import zlib

def build(source, fmt, count):
    fmt=fmt;h=lambda b:hashlib.new(fmt,b).digest();objects={}
    def store(kind,body):
        oid=h(kind.encode()+b' '+str(len(body)).encode()+b'\0'+body);objects[oid]=(kind,body);return oid
    top=[]
    for start in range(0,count,500):
        children=[]
        for i in range(start,min(start+500,count)):
            oid=store('blob',f'file {i:06d}\n'.encode());children.append(f'100644 file{i:06d}\0'.encode()+oid)
        tree=store('tree',b''.join(children));top.append(f'40000 dir{start//500:06d}\0'.encode()+tree)
    tree=store('tree',b''.join(top));tip=store('commit',f'tree {tree.hex()}\nauthor Native <test@example.invalid> 1 +0000\ncommitter Native <test@example.invalid> 1 +0000\n\nscale import\n'.encode())
    pack=bytearray(b'PACK'+struct.pack('>II',2,len(objects)));index=[]
    for oid,(kind,body) in objects.items():
        offset=len(pack);size=len(body);header=bytearray();byte=({'commit':1,'tree':2,'blob':3}[kind]<<4)|(size&15);size>>=4
        while size:header.append(byte|128);byte=size&127;size>>=7
        header.append(byte);entry=header+zlib.compress(body);pack.extend(entry);index.append((oid,zlib.crc32(entry)&0xffffffff,offset))
    checksum=h(pack);pack.extend(checksum);index.sort();fanout=[sum(oid[0]<=n for oid,_,_ in index) for n in range(256)]
    idx=b'\xfftOc'+struct.pack('>I',2)+struct.pack('>256I',*fanout)+b''.join(x[0]for x in index)+b''.join(struct.pack('>I',x[1])for x in index)+b''.join(struct.pack('>I',x[2])for x in index)+checksum;idx+=h(idx)
    (source/'objects/pack').mkdir(parents=True,exist_ok=True);name='pack-'+checksum.hex();(source/'objects/pack'/f'{name}.pack').write_bytes(pack);(source/'objects/pack'/f'{name}.idx').write_bytes(idx)
    (source/'refs/heads').mkdir(parents=True,exist_ok=True);(source/'refs/heads/main').write_text(tip.hex()+'\n');(source/'HEAD').write_text('ref: refs/heads/main\n');(source/'config').write_text('[core]\nbare=true\nrepositoryformatversion='+('1\n[extensions]\nobjectformat=sha256\n'if fmt=='sha256'else'0\n'))
    return tip.hex(), {oid.hex():(kind,body) for oid,(kind,body) in objects.items()}, checksum.hex()
