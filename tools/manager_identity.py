#!/usr/bin/env python3
"""从 FinaSU 管理器 APK 解出内核编译需要的身份参数。

为什么要这个：
    FinaSU 的 kernel/Kbuild 在没传 KSU_EXPECTED_SIZE2 / KSU_EXPECTED_HASH2 时，
    会把 FINASU_TRUSTED_HASH 回落到 KSU_EXPECTED_HASH（官方 KernelSU 证书
    c371061b…）。apk_sign_keys[0] 名字写着 "FinaSU"，实际信任的却是 KernelSU
    签名 —— 于是管理器加冕落在 KernelSU 管理器上，FinaSU 管理器不被识别。

做法：
    包名走二进制 AXML 解 <manifest package=…>（不能字符串搜，pool 里还有类名和
    permission 名）；证书走 APK Signing Block → v2 → signers[0] → signed_data →
    digests（跳过）→ certificates[0]，对该 DER 求 SHA-256，长度即 DER 长度 ——
    与内核 apk_sign.c 的 check_block 口径一致。

输出（默认 key=value，可直接 >> $GITHUB_OUTPUT）：
    package=me.yuki.fina
    version_code=33174
    cert_size=0x2cc
    cert_size_dec=716
    cert_sha256=2d89b50a…
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
import zipfile
from pathlib import Path


def _string_pool(d: bytes, start: int):
    hdr_size = struct.unpack_from("<H", d, start + 2)[0]
    count = struct.unpack_from("<I", d, start + 8)[0]
    flags = struct.unpack_from("<I", d, start + 16)[0]
    strings_start = struct.unpack_from("<I", d, start + 20)[0]
    base = start + strings_start
    out = []
    utf8 = bool(flags & 0x100)
    offsets = start + hdr_size
    for i in range(count):
        off = struct.unpack_from("<I", d, offsets + i * 4)[0]
        p = base + off
        if utf8:
            def varint(b):
                v = 0
                sh = 0
                while True:
                    c = d[b]
                    b += 1
                    v |= (c & 0x7F) << sh
                    sh += 7
                    if not c & 0x80:
                        return v, b
            ln, p = varint(p)
            _b, p = varint(p)
            out.append(d[p:p + ln].decode("utf-8", "replace"))
        else:
            ln = struct.unpack_from("<H", d, p)[0]
            out.append(d[p + 2:p + 2 + ln * 2].decode("utf-16-le", "replace"))
    return out


def manifest_info(apk: Path) -> dict:
    with zipfile.ZipFile(apk) as z:
        d = z.read("AndroidManifest.xml")
    pool = None
    pkg = None
    ver_code = None
    p = 8
    while p + 8 <= len(d):
        ctype, _hsize, csize = struct.unpack_from("<HHI", d, p)
        if csize == 0:
            break
        if ctype == 0x0001 and pool is None:
            pool = _string_pool(d, p)
        elif ctype == 0x0102 and pkg is None:  # START_TAG
            _ns_idx, name_idx = struct.unpack_from("<II", d, p + 16)
            attr_start = struct.unpack_from("<H", d, p + 24)[0]
            attr_size = struct.unpack_from("<H", d, p + 26)[0]
            attr_count = struct.unpack_from("<H", d, p + 28)[0]
            if pool[name_idx] == "manifest":
                for i in range(attr_count):
                    a = p + 16 + attr_start + i * attr_size
                    _ns, nm, raw = struct.unpack_from("<III", d, a)
                    data = struct.unpack_from("<I", d, a + 16)[0]
                    key = pool[nm]
                    if key == "package":
                        pkg = pool[raw] if raw != 0xFFFFFFFF else pool[data]
                    elif key == "versionCode":
                        ver_code = data
        p += csize
    return dict(package=pkg, version_code=ver_code)


def v2_cert(apk: Path) -> dict:
    d = apk.read_bytes()
    magic = d.rfind(b"APK Sig Block 42")
    if magic < 0:
        raise SystemExit("APK 里没有 APK Signing Block —— v1-only 签名不适用于内核校验")
    size = struct.unpack_from("<Q", d, magic - 8)[0]
    start = magic + 16 - size - 8
    pos = start + 8
    end = magic - 8
    while pos < end:
        ln = struct.unpack_from("<Q", d, pos)[0]
        pid = struct.unpack_from("<I", d, pos + 8)[0]
        if pid == 0x7109871A:  # v2
            blk = d[pos + 12:pos + 8 + ln]

            def lp(b, o):
                return o + 4, o + 4 + struct.unpack_from("<I", b, o)[0]

            o = 0
            o, _ = lp(blk, o)            # signers
            o, _ = lp(blk, o)            # signer[0]
            o, _ = lp(blk, o)            # signed data
            o, digests_end = lp(blk, o)  # digests 序列
            o = digests_end              # 必须跳过摘要序列
            o, _ = lp(blk, o)            # certificates 序列
            clen = struct.unpack_from("<I", blk, o)[0]
            o += 4
            cert = blk[o:o + clen]
            if cert[:2] != b"\x30\x82":
                raise SystemExit(f"certificates[0] 不是 DER SEQUENCE（头 {cert[:4].hex()}）")
            return dict(size=clen, sha256=hashlib.sha256(cert).hexdigest())
        pos += 8 + ln
    raise SystemExit("v2 签名块里没有 0x7109871A 分区")


def read_trusted_slot(module: Path) -> dict:
    """解析 ET_REL ELF64 里 apk_sign_keys[0]，返回它实际信任的 size / sha256 / name。

    apk_sign_key_t = { unsigned size; const char *sha256; unsigned flags;
                       const char *name; } —— 64 位下每项 32 字节。
    两个指针字段在 .o 里靠 .rela<section> 重定位填充，必须解重定位才能拿到真串；
    只检查字符串是否存在，无法证明 trusted 槽位填的是谁的证书。
    """
    d = module.read_bytes()
    if d[:4] != b"\x7fELF" or d[4] != 2:
        raise SystemExit("不是 ELF64 目标文件")
    shoff, = struct.unpack_from("<Q", d, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", d, 0x3A)
    keys = "name typ flags addr off size link info align entsize".split()
    sections = [dict(zip(keys, struct.unpack_from("<IIQQQQIIQQ", d, shoff + i * shentsize)))
                for i in range(shnum)]
    shstr = sections[shstrndx]

    def section_name(n):
        start = shstr["off"] + n
        return d[start:d.index(b"\0", start)].decode()

    for s in sections:
        s["sn"] = section_name(s["name"])

    symtab = next(s for s in sections if s["typ"] == 2)
    strtab = sections[symtab["link"]]
    syms = []
    for o in range(symtab["off"], symtab["off"] + symtab["size"], 24):
        n, _info, _other, idx, val, sz = struct.unpack_from("<IBBHQQ", d, o)
        start = strtab["off"] + n
        syms.append(dict(name=d[start:d.index(b"\0", start)].decode(),
                         idx=idx, val=val, size=sz))
    key = next(x for x in syms if x["name"] == "apk_sign_keys")
    sec = sections[key["idx"]]
    rela = next(s for s in sections if s["sn"] == ".rela" + sec["sn"])
    rels = {}
    for o in range(rela["off"], rela["off"] + rela["size"], 24):
        off, info, add = struct.unpack_from("<QQq", d, o)
        rels[off] = (info >> 32, add)

    def resolve(field):
        si, add = rels[field]
        sym = syms[si]
        s = sections[sym["idx"]]
        start = s["off"] + sym["val"] + add
        return d[start:d.index(b"\0", start)].decode()

    base = sec["off"] + key["val"]
    size, = struct.unpack_from("<I", d, base)
    return dict(size=size, sha256=resolve(key["val"] + 8), name=resolve(key["val"] + 24))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("apk", nargs="?")
    ap.add_argument("--format", choices=("github", "json"), default="github")
    ap.add_argument("--verify-module", help="编译产物 kernelsu.ko，校验第 0 信任槽是否等于本 APK")
    args = ap.parse_args()

    if not args.apk:
        raise SystemExit("需要 APK 路径")

    apk = Path(args.apk)
    info = manifest_info(apk)
    cert = v2_cert(apk)

    if not info["package"]:
        raise SystemExit("解不出 <manifest package=…>")

    fields = {
        "package": info["package"],
        "version_code": info["version_code"] or 0,
        "cert_size": f"0x{cert['size']:x}",
        "cert_size_dec": cert["size"],
        "cert_sha256": cert["sha256"],
    }

    if args.verify_module:
        mod = Path(args.verify_module)
        try:
            slot = read_trusted_slot(mod)
        except (StopIteration, KeyError):
            # static const 数组在单行表（KSU_PRESET_MANAGER_MASK=0）时会被编译器
            # 内联成匿名常量，符号表里就没有 apk_sign_keys 了。降级为字节级检查。
            slot = None

        if slot:
            ok = (slot["size"] == cert["size"]
                  and slot["sha256"] == cert["sha256"]
                  and slot["name"] == "FinaSU")
            print(f"[verify] 模块第 0 信任槽: name={slot['name']} "
                  f"size=0x{slot['size']:x} sha256={slot['sha256']}", file=sys.stderr)
        else:
            blob = mod.read_bytes()
            ok = cert["sha256"].encode() in blob
            print("[verify] 符号表里没有 apk_sign_keys（单行表被内联），"
                  "降级为字节级检查", file=sys.stderr)

        print(f"[verify] 目标管理器     : name=FinaSU "
              f"size={fields['cert_size']} sha256={fields['cert_sha256']}", file=sys.stderr)
        if not ok:
            print("[verify] 不一致 —— 这个 ko 不会把 FinaSU 管理器认成 trusted", file=sys.stderr)
            return 1
        print("[verify] 一致", file=sys.stderr)

    if args.format == "json":
        print(json.dumps(fields, ensure_ascii=False, indent=1))
    else:
        for k, v in fields.items():
            print(f"{k}={v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
