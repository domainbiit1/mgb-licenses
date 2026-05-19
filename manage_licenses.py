# -*- coding: utf-8 -*-
"""
MGB Bot — License Manager (CLI tool cho admin)
==============================================
Tool CHAY OFFLINE tren may admin. Edit licenses.json roi sign bang Ed25519.

Cai dat 1 lan:
  pip install cryptography

Workflow:
  1. python manage_licenses.py gen-keys        # tao private_key.pem + in public key
  2. python manage_licenses.py init            # tao licenses.json trong
  3. python manage_licenses.py add --owner "Khach A" --days 30
       -> in ra license_key. Gui cho khach.
  4. Khach gui Machine ID lai
  5. python manage_licenses.py bind --key MGB-XXXX --hwid abcdef-...
  6. git add licenses.signed.json && git commit -m "..." && git push
  7. Khach activate trong app

Cac lenh khac:
  list                          # xem toan bo
  revoke   --key MGB-XXXX       # khoa
  delete   --key MGB-XXXX       # xoa
  extend   --key MGB-XXXX --days 30
  reset-hw --key MGB-XXXX       # cho phep activate may khac
  sign                          # re-sign file (it khi can goi truc tiep)
  show     --key MGB-XXXX       # xem chi tiet 1 entry
"""

import os, sys, json, argparse, secrets
from datetime import datetime, timedelta, timezone

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey)
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("ERROR: thieu library 'cryptography'. Run: pip install cryptography")
    sys.exit(1)


# =============================================================================
# CONFIG
# =============================================================================
PRIVATE_KEY_FILE = "private_key.pem"
PLAIN_FILE       = "licenses.json"          # file lam viec (chua sign)
SIGNED_FILE      = "licenses.signed.json"   # file commit len GitHub (da sign)
PRODUCT_CODE     = "MGB-BOT-V4"


# =============================================================================
# CRYPTO HELPERS
# =============================================================================
def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def load_private_key():
    if not os.path.exists(PRIVATE_KEY_FILE):
        print(f"ERROR: khong tim thay {PRIVATE_KEY_FILE}")
        print("Chay 'gen-keys' truoc.")
        sys.exit(1)
    with open(PRIVATE_KEY_FILE, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def sign_data(data):
    priv = load_private_key()
    sig = priv.sign(_canonical(data))
    return sig.hex()


# =============================================================================
# FILE IO
# =============================================================================
def load_plain():
    if not os.path.exists(PLAIN_FILE):
        return {"version": 1, "issued_at": _now_iso(),
                 "product": PRODUCT_CODE, "licenses": []}
    with open(PLAIN_FILE) as f:
        return json.load(f)


def save_plain(data):
    with open(PLAIN_FILE, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def write_signed(data):
    """Write licenses.signed.json voi data + signature."""
    # Cap nhat issued_at
    data["issued_at"] = _now_iso()
    sig = sign_data(data)
    bundle = {"data": data, "signature": sig}
    with open(SIGNED_FILE, "w") as f:
        json.dump(bundle, f, indent=2, ensure_ascii=False)


def commit_changes(data, action_msg):
    """Save plain + sign + write signed. Goi sau moi thao tac."""
    save_plain(data)
    write_signed(data)
    print(f"  -> Da update {PLAIN_FILE} + {SIGNED_FILE}")
    print(f"  -> Tiep theo: git add {SIGNED_FILE} && git commit -m \"{action_msg}\" && git push")


def _now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _gen_key_str():
    """Sinh key dang MGB-XXXX-XXXX-XXXX-XXXX (16 hex / 4 nhom)."""
    parts = [secrets.token_hex(2).upper() for _ in range(4)]
    return "MGB-" + "-".join(parts)


def _find(data, key):
    key = key.strip().upper()
    for i, L in enumerate(data["licenses"]):
        if L["key"].strip().upper() == key:
            return i, L
    return -1, None


# =============================================================================
# COMMANDS
# =============================================================================
def cmd_gen_keys(args):
    if os.path.exists(PRIVATE_KEY_FILE) and not args.force:
        print(f"!! {PRIVATE_KEY_FILE} da ton tai. Dung --force de overwrite "
               f"(canh bao: moi license da phat hanh se INVALID neu doi key).")
        return
    priv = Ed25519PrivateKey.generate()
    pub  = priv.public_key()

    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)

    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(priv_pem)
    try:
        os.chmod(PRIVATE_KEY_FILE, 0o600)
    except Exception: pass

    pub_hex = pub_bytes.hex()
    print("=" * 60)
    print(f"PRIVATE KEY saved to: {PRIVATE_KEY_FILE}")
    print(f"   --> CHU Y: KHONG commit file nay. Backup an toan.")
    print(f"   --> Them vao .gitignore:  {PRIVATE_KEY_FILE}")
    print()
    print(f"PUBLIC KEY (paste vao license_client.py - PUBLIC_KEY_HEX):")
    print()
    print(f"  PUBLIC_KEY_HEX = \"{pub_hex}\"")
    print()
    print("=" * 60)


def cmd_init(args):
    if os.path.exists(PLAIN_FILE) and not args.force:
        print(f"!! {PLAIN_FILE} da ton tai. Dung --force de overwrite.")
        return
    data = {"version": 1, "issued_at": _now_iso(),
             "product": PRODUCT_CODE, "licenses": []}
    commit_changes(data, "init licenses")


def cmd_add(args):
    data = load_plain()
    key = _gen_key_str()
    exp = (datetime.now(timezone.utc) + timedelta(days=args.days))\
            .replace(microsecond=0).isoformat()
    entry = {
        "key":        key,
        "owner":      args.owner or "",
        "note":       args.note or "",
        "product":    PRODUCT_CODE,
        "hwid":       (args.hwid or "").strip(),
        "expires_at": exp,
        "status":     "active",
        "created_at": _now_iso(),
    }
    data["licenses"].append(entry)
    commit_changes(data, f"add license for {args.owner or 'unknown'}")
    print()
    print(f"   LICENSE KEY:  {key}")
    print(f"   OWNER:        {args.owner or '—'}")
    print(f"   DAYS:         {args.days}")
    print(f"   EXPIRES:      {exp}")
    print(f"   HWID:         {entry['hwid'] or '(chua bind — cho user gui Machine ID)'}")


def cmd_bind(args):
    data = load_plain()
    i, L = _find(data, args.key)
    if i < 0: print(f"!! Khong tim thay key {args.key}"); return
    L["hwid"] = args.hwid.strip()
    commit_changes(data, f"bind hwid for {args.key}")
    print(f"   {args.key}  -> bound to HWID {L['hwid'][:24]}...")


def cmd_revoke(args):
    data = load_plain()
    i, L = _find(data, args.key)
    if i < 0: print(f"!! Khong tim thay key {args.key}"); return
    L["status"] = "revoked"
    commit_changes(data, f"revoke {args.key}")
    print(f"   {args.key}  -> REVOKED")


def cmd_delete(args):
    data = load_plain()
    i, L = _find(data, args.key)
    if i < 0: print(f"!! Khong tim thay key {args.key}"); return
    L["status"] = "deleted"
    commit_changes(data, f"delete {args.key}")
    print(f"   {args.key}  -> DELETED")


def cmd_extend(args):
    data = load_plain()
    i, L = _find(data, args.key)
    if i < 0: print(f"!! Khong tim thay key {args.key}"); return
    try:
        exp = datetime.fromisoformat(L["expires_at"].replace("Z","+00:00"))
        if exp.tzinfo is None: exp = exp.replace(tzinfo=timezone.utc)
    except Exception:
        exp = datetime.now(timezone.utc)
    now = datetime.now(timezone.utc)
    start = exp if exp > now else now
    new_exp = (start + timedelta(days=args.days)).replace(microsecond=0).isoformat()
    L["expires_at"] = new_exp
    L["status"] = "active"  # re-activate khi extend
    commit_changes(data, f"extend {args.key} {args.days:+d} days")
    print(f"   {args.key}  -> NEW EXPIRES: {new_exp}")


def cmd_reset_hw(args):
    data = load_plain()
    i, L = _find(data, args.key)
    if i < 0: print(f"!! Khong tim thay key {args.key}"); return
    L["hwid"] = ""
    commit_changes(data, f"reset HWID for {args.key}")
    print(f"   {args.key}  -> HWID cleared (user co the activate may moi)")


def cmd_list(args):
    data = load_plain()
    licenses = data["licenses"]
    if not licenses:
        print("(empty)"); return
    print(f"{'KEY':<22} {'OWNER':<20} {'STATUS':<10} {'EXPIRES':<22} {'HWID':<12}")
    print("-" * 90)
    for L in licenses:
        hwid_disp = L["hwid"][:8] + "..." if L["hwid"] else "(none)"
        print(f"{L['key']:<22} {L.get('owner','')[:18]:<20} "
               f"{L.get('status','active'):<10} {L['expires_at']:<22} "
               f"{hwid_disp:<12}")


def cmd_show(args):
    data = load_plain()
    i, L = _find(data, args.key)
    if i < 0: print(f"!! Khong tim thay key {args.key}"); return
    print(json.dumps(L, indent=2, ensure_ascii=False))


def cmd_sign(args):
    """Re-sign file (it khi can dung. Tu dong sau moi cmd)."""
    data = load_plain()
    write_signed(data)
    print(f"   Re-signed {SIGNED_FILE}")


# =============================================================================
# CLI PARSER
# =============================================================================
def main():
    p = argparse.ArgumentParser(description="MGB Bot License Manager")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_gen = sub.add_parser("gen-keys", help="Sinh cap private/public key Ed25519")
    p_gen.add_argument("--force", action="store_true")
    p_gen.set_defaults(func=cmd_gen_keys)

    p_init = sub.add_parser("init", help="Tao licenses.json trong")
    p_init.add_argument("--force", action="store_true")
    p_init.set_defaults(func=cmd_init)

    p_add = sub.add_parser("add", help="Tao license moi")
    p_add.add_argument("--owner", help="Ten khach")
    p_add.add_argument("--days", type=int, default=30)
    p_add.add_argument("--note", default="")
    p_add.add_argument("--hwid", default="", help="(optional) bind ngay HWID")
    p_add.set_defaults(func=cmd_add)

    p_bind = sub.add_parser("bind", help="Bind HWID cho 1 license")
    p_bind.add_argument("--key", required=True)
    p_bind.add_argument("--hwid", required=True, help="HWID full hoac short do user gui")
    p_bind.set_defaults(func=cmd_bind)

    p_revoke = sub.add_parser("revoke", help="Khoa license")
    p_revoke.add_argument("--key", required=True)
    p_revoke.set_defaults(func=cmd_revoke)

    p_del = sub.add_parser("delete", help="Xoa license")
    p_del.add_argument("--key", required=True)
    p_del.set_defaults(func=cmd_delete)

    p_ext = sub.add_parser("extend", help="Gia han license")
    p_ext.add_argument("--key", required=True)
    p_ext.add_argument("--days", type=int, required=True)
    p_ext.set_defaults(func=cmd_extend)

    p_reset = sub.add_parser("reset-hw", help="Reset HWID binding (cho doi may)")
    p_reset.add_argument("--key", required=True)
    p_reset.set_defaults(func=cmd_reset_hw)

    p_list = sub.add_parser("list", help="Xem toan bo license")
    p_list.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", help="Xem chi tiet 1 license")
    p_show.add_argument("--key", required=True)
    p_show.set_defaults(func=cmd_show)

    p_sign = sub.add_parser("sign", help="Re-sign file")
    p_sign.set_defaults(func=cmd_sign)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
