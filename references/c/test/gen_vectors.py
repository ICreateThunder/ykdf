#!/usr/bin/env python3
"""Emit vectors/v1.json as a C header for the conformance runner.

The C reference reads the same canonical vector file as every other
implementation; this just transcribes it into a compile-time table so the C
test needs no runtime JSON parser. It vendors no data - the header is
regenerated from vectors/v1.json on every build (see the Makefile).
"""
import json
import sys


def cstr(s: str) -> str:
    # The big ML-DSA/ML-KEM key literals exceed the C99 guaranteed minimum
    # string length; the Makefile passes -Wno-overlength-strings for the test.
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def main() -> int:
    with open(sys.argv[1], encoding="utf-8") as f:
        suite = json.load(f)

    out = [
        "/* Generated from vectors/v1.json by test/gen_vectors.py. Do not edit. */",
        f"static const char *const VECTORS_VERSION = {cstr(suite['version'])};",
        "static const vector_t VECTORS[] = {",
    ]
    for v in suite["vectors"]:
        outputs = list(v["output"].items())
        if len(outputs) > 2:
            raise SystemExit(f"vector {v['name']} has >2 output fields")
        while len(outputs) < 2:
            outputs.append((None, None))
        pairs = ", ".join(
            "{NULL, NULL}" if k is None else f"{{{cstr(k)}, {cstr(val)}}}"
            for k, val in outputs
        )
        out.append(
            "    {"
            f"{cstr(v['name'])}, {cstr(v['pipeline'])}, {cstr(v['profile'])}, "
            f"{cstr(v['purpose'])}, {v['index']}, {v.get('length', 0)}, "
            f"{cstr(v['ikm_hex'])}, {cstr(v.get('passphrase', ''))}, "
            f"{cstr(v['master_key_hex'])}, {cstr(v['expanded_hex'])}, "
            f"{{{pairs}}}"
            "},"
        )
    out.append("};")
    out.append(f"static const size_t VECTORS_LEN = {len(suite['vectors'])};")
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
