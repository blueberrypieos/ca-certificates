#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 The Blueberry Pie OS Authors
import base64
import collections
import os
import re
import sys


def objects(path):
    out, obj, field, octal = [], {}, None, None
    data = False
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not data:
                data = line.startswith("BEGINDATA")
                continue
            if octal is not None:
                if line == "END":
                    obj[field], octal = bytes(octal), None
                else:
                    octal += [int(o, 8) for o in re.findall(r"\\([0-3][0-7][0-7])", line)]
                continue
            if line.startswith("#"):
                continue
            if not line.strip():
                if obj:
                    out.append(obj)
                obj = {}
                continue
            parts = line.split(" ", 2)
            field = parts[0]
            if parts[1] == "MULTILINE_OCTAL":
                octal = []
            else:
                obj[field] = parts[2] if len(parts) > 2 else None
    if obj:
        out.append(obj)
    return out


def blacklist(path):
    with open(path, encoding="utf-8") as f:
        return {line.split("#", 1)[0].strip() for line in f
                if line.strip() and not line.startswith("#")} - {""}


def pems(text):
    return [base64.b64decode("".join(m.split()))
            for m in re.findall(r"-----BEGIN CERTIFICATE-----\n(.*?)-----END CERTIFICATE-----",
                                text, re.S)]


def main():
    if len(sys.argv) != 5:
        sys.exit("usage: check.py CERTDATA BLACKLIST BUNDLE CRTDIR")
    certdata, blpath, bundle, crtdir = sys.argv[1:]
    objs = objects(certdata)
    bl = blacklist(blpath)
    certs = [o for o in objs if o.get("CKA_CLASS") == "CKO_CERTIFICATE"]
    trusts = [o for o in objs if o.get("CKA_CLASS") == "CKO_NSS_TRUST"]
    key = lambda o: (o["CKA_ISSUER"], o["CKA_SERIAL_NUMBER"])
    server = {key(t) for t in trusts if t.get("CKA_TRUST_SERVER_AUTH") == "CKT_NSS_TRUSTED_DELEGATOR"}
    banned = {key(t) for t in trusts if t.get("CKA_LABEL") in bl}
    want = collections.Counter(c["CKA_VALUE"] for c in certs
                               if key(c) in server and key(c) not in banned)
    unwanted = {c["CKA_VALUE"]: c["CKA_LABEL"] for c in certs if key(c) in banned}
    problems = []
    if len(trusts) != len(certs) or len({key(t) for t in trusts}) != len(trusts):
        problems.append("certdata.txt: %d certificates, %d trust objects (%d distinct)"
                        % (len(certs), len(trusts), len({key(t) for t in trusts})))
    if not want:
        problems.append("certdata.txt: no certificate trusted for servers")
    with open(bundle) as f:
        got = collections.Counter(pems(f.read()))
    files = collections.Counter()
    for name in sorted(os.listdir(crtdir)):
        if name.endswith(".crt"):
            with open(os.path.join(crtdir, name)) as f:
                ders = pems(f.read())
            if len(ders) != 1:
                problems.append("%s: %d certificates, not one" % (name, len(ders)))
            files.update(ders)
    for what, have in (("the bundle", got), (crtdir, files)):
        if have != want:
            problems.append("%s: %d certificates, %d missing, %d not wanted, %d twice"
                            % (what, sum(have.values()), len(want - have), len(have - want),
                               sum(1 for n in have.values() if n > 1)))
        problems += ["%s has blacklisted %s" % (what, label)
                     for der, label in unwanted.items() if der in have]
    if problems:
        sys.exit("check.py: " + "\n  ".join(problems))
    print("ca-certificates: %d roots, as certdata.txt has them (of %d certificates; %d trusted "
          "for servers; %d blacklisted by label, none of them in the bundle)"
          % (sum(want.values()), len(certs), len(server), len(banned)))


if __name__ == "__main__":
    main()
