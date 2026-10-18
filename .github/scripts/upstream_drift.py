import argparse
import os
import re
import sys

CONSTS = [
    ("PCAP_IF_", "u32"),
    ("PCAP_CHAR_ENC_", "u32"),
    ("PCAP_WARNING", "c_int"),
    ("PCAP_ERROR", "c_int"),
]

ENUMS = [
    ("PCAP_TSTAMP_PRECISION_", "Precision", "src/capture/mod.rs"),
    ("PCAP_TSTAMP_", "TimestampType", "src/capture/inactive.rs"),
]

RAW = "src/raw.rs"
LINKTYPE = "src/linktype.rs"
CHANGELOG = "CHANGELOG.md"
UNRELEASED = "## [Unreleased]\n"
ADDED = "### Added\n"

# libpcap assigns link types in order, so a new one is just above the highest the crate names.
AHEAD = 64

HEADERS = ["pcap/pcap.h", "pcap.h"]
DLT_HEADERS = ["pcap/dlt.h", "pcap-bpf.h", "bpf/net/bpf.h"]
# The numbers the crate names are the savefile ones, which libpcap keeps in its own source.
LINK_SOURCES = ["pcap-common.c", "savefile.c"]

DEF = re.compile(
    r"^#define\s+(PCAP_[A-Z0-9_]+)\s+(-?(?:0x)?[0-9a-fA-F]+)[uUlL]*\s*(?:/\*|$)", re.M
)
CONST = re.compile(r"^pub const (PCAP_[A-Z0-9_]+): \w+ = (-?(?:0x)?[0-9a-fA-F]+);", re.M)
VAR = re.compile(r"^\s+\w+ = (-?[0-9]+),", re.M)
DLT = re.compile(r"^#define\s+DLT_([A-Z0-9_]+)\s+(\S+)", re.M)
LINK = re.compile(r"^#define\s+LINKTYPE_([A-Z0-9_]+)\s+(\S+)", re.M)
LT = re.compile(r"^    pub const ([A-Z0-9_]+): Self = Self\(([0-9]+)\);$", re.M)


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def find(root, names):
    for name in names:
        path = os.path.join(root, name)
        if os.path.exists(path):
            return path
    raise SystemExit(f"None of {', '.join(names)} is in {root}")


def literal(value, kind):
    return f"0x{value:08x}" if kind == "u32" else str(value)


def variants(path, name):
    body = read(path).split(f"pub enum {name} {{", 1)[1].split("\n}", 1)[0]
    return {int(value) for value in VAR.findall(body)}


def split(defs, prefixes):
    groups = {prefix: {} for prefix in prefixes}
    for name, value in defs.items():
        matches = [prefix for prefix in prefixes if name.startswith(prefix)]
        if matches:
            groups[max(matches, key=len)][name] = value
    return groups


def linktypes(libpcap):
    dlt = dict(DLT.findall(read(find(libpcap, DLT_HEADERS))))
    resolved = {}
    for name, value in LINK.findall(read(find(libpcap, LINK_SOURCES))):
        if value.startswith("DLT_"):
            value = dlt.get(value[4:], value)
        if value.isdigit() and "MATCHING_" not in name:
            resolved[name] = int(value)
    return resolved


def plan(libpcap, crate):
    header = find(libpcap, HEADERS)
    defs = {name: int(value, 0) for name, value in DEF.findall(read(header))}
    groups = split(defs, [prefix for prefix, _ in CONSTS] + [p for p, _, _ in ENUMS])
    consts = {
        name: int(value, 0)
        for name, value in CONST.findall(read(os.path.join(crate, RAW)))
    }
    named = {
        int(value): name
        for name, value in LT.findall(read(os.path.join(crate, LINKTYPE)))
    }

    links, missing, manual = [], [], []

    # A family the header stopped declaring would otherwise pass with no defines to compare.
    for prefix, group in groups.items():
        if not group:
            manual.append(f"`{prefix}*` is not in {os.path.basename(header)}")

    for prefix, kind in CONSTS:
        for name, value in groups[prefix].items():
            if name not in consts:
                missing.append((name, value, kind))
            elif consts[name] != value:
                manual.append(f"`{name}` is {consts[name]} in {RAW} and {value} in libpcap")

    for prefix, name, path in ENUMS:
        values = variants(os.path.join(crate, path), name)
        for define, value in groups[prefix].items():
            if value not in values:
                manual.append(f"`{define}` = {value} has no `{name}` variant in {path}")

    top = max(named)
    for name, value in sorted(linktypes(libpcap).items(), key=lambda item: item[1]):
        if value not in named:
            if top < value <= top + AHEAD:
                links.append((name, value))
        elif named[value] != name:
            manual.append(f"`LINKTYPE_{name}` = {value} is named `{named[value]}` in {LINKTYPE}")

    return links, missing, manual, groups


def apply_consts(text, groups):
    lines = text.split("\n")
    at = [
        n
        for n, line in enumerate(lines)
        if any(line.startswith(f"pub const {prefix}") for prefix, _ in CONSTS)
    ]
    if any(lines[n].strip() and n not in at for n in range(at[0], at[-1])):
        raise SystemExit(f"{RAW} has more than the mirrored constants between "
                         f"{lines[at[0]]} and {lines[at[-1]]}")

    kept = {lines[n].split()[2].rstrip(":"): lines[n] for n in at}
    block = []
    for prefix, kind in CONSTS:
        if not groups[prefix]:
            continue
        if block:
            block.append("")
        block += [
            kept.get(name, f"pub const {name}: {kind} = {literal(value, kind)};")
            for name, value in groups[prefix].items()
        ]
    return "\n".join(lines[: at[0]] + block + lines[at[-1] + 1 :])


def apply_linktypes(text, links):
    *_, last = LT.finditer(text)
    added = "".join(f"    pub const {name}: Self = Self({value});\n" for name, value in links)
    return text[: last.end() + 1] + added + text[last.end() + 1 :]


def apply_changelog(text, version):
    entry = f"- Sync new constants with libpcap {version} release."
    if f"libpcap {version} release." in text:
        return text
    if UNRELEASED not in text:
        raise SystemExit(f"{CHANGELOG} has no {UNRELEASED.strip()} section to write under")

    head, rest = text.split(UNRELEASED, 1)
    section, release, rest = rest.partition("\n## ")
    if ADDED in section:
        before, listed = section.split(ADDED, 1)
        listed, heading, after = listed.partition("\n### ")
        section = f"{before}{ADDED}{listed.rstrip()}\n{entry}\n{heading}{after}"
    else:
        section = f"\n{ADDED}\n{entry}\n{section.lstrip()}"
    return f"{head}{UNRELEASED}{section}{release}{rest}"


def body(tag, links, consts, manual, run):
    release = f"https://github.com/the-tcpdump-group/libpcap/releases/tag/{tag}"
    version = tag.removeprefix("libpcap-")
    found = len(links) + len(consts) + len(manual)
    out = [f"⚠️ **Attention:** A recent comparison has found {found} constant"
           f" change{'' if found == 1 else 's'} in [libpcap {version}]({release}):", ""]

    if links:
        out += ["### 🔗 Link types", "", "| Link type | Value |", "| --- | --- |"]
        out += [f"| `Linktype::{name}` | {value} |" for name, value in links] + [""]
    if consts:
        out += ["### 🔒 Constants", "", "| Constant | Value |", "| --- | --- |"]
        out += [f"| `raw::{name}` | `{literal(value, kind)}` |" for name, value, kind in consts]
        out += [""]
    if manual:
        out += ["### 👀 Requires manual review", ""]
        out += [f"- {line}" for line in manual]
        out += [
            "",
            "Renaming a link type is a breaking change, and a new enum variant requires a"
            " doc comment and, for a release newer than the minimum this crate supports, a"
            " `#[cfg(libpcap_x_y_z)]` gate. These entries are therefore left unmodified."
            " Address them on a separate branch, because this one is rebuilt from the base"
            " on every run and any commit added here is overwritten.",
            "",
        ]

    out += ["---", "",
            f"Automated by `.github/scripts/upstream_drift.py` against libpcap {version}"
            f"{f' in [this run]({run})' if run else ''}."]
    return "\n".join(out) + "\n"


def main(args):
    links, consts, manual, groups = plan(args.libpcap, args.source_dir)
    if not (links or consts or manual):
        checked = sum(len(group) for group in groups.values())
        print(f"{checked} constants and the link types match libpcap")
        return 0

    print("The crate does not match libpcap:", file=sys.stderr)
    for name, value, _ in consts:
        print(f"  {name} = {value} has no constant in {RAW}", file=sys.stderr)
    for name, value in links:
        print(f"  {name} = {value} has no Linktype constant", file=sys.stderr)
    for line in manual:
        print("  " + line.replace("`", ""), file=sys.stderr)

    if args.write and (consts or links):
        path = os.path.join(args.source_dir, CHANGELOG)
        write(path, apply_changelog(read(path), args.tag.removeprefix("libpcap-")))
    if args.write and consts:
        path = os.path.join(args.source_dir, RAW)
        write(path, apply_consts(read(path), groups))
    if args.write and links:
        path = os.path.join(args.source_dir, LINKTYPE)
        write(path, apply_linktypes(read(path), links))
    if args.pr_body:
        write(args.pr_body, body(args.tag, links, consts, manual, args.run))

    return 3 if manual else 2


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Check link types and constants against a libpcap release"
    )

    parser.add_argument("--libpcap", type=str, required=True,
                        help="Path to a checkout of libpcap")
    parser.add_argument("--source-dir", type=str, default=".",
                        help="Path to the root of the crate")
    parser.add_argument("--write", action="store_true",
                        help="Add the new constants to the crate and the changelog, leaving "
                             "the entries that require manual review")
    parser.add_argument("--pr-body", type=str,
                        help="Destination path for the generated pull request body")
    parser.add_argument("--tag", type=str, required=True,
                        help="Tag of the libpcap release under comparison")
    parser.add_argument("--run", type=str,
                        help="URL of the workflow run to cite in the pull request body")

    args = parser.parse_args()

    exit(main(args))
