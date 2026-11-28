"""Replay difference report from files: the remittances (835) of two or more claims systems, old against new or any number of them,
and optionally the gate's decisions on the same 837 claims, each side named in the report.

``report_files`` reads the 835 and 837 files (read-only, no network) and writes the canonical report
(app/right_rail_replay_diff.py) to the named file. With a ``system_map`` (``diff.load_map``) every line names the system and owner at
fault. It never writes an input and never seals into a live store: the gate's side, when 837 files are given, is
decided by ``decide(reads, store)`` (a decide marked ``wants_835`` also gets the 835 reads), which the deployment supplies, into a fresh temporary store folder that this tool creates for the
run and removes afterwards. ``decide`` returns ``(sent, left, rows)``: what ``right_rail_gate_ffs.requests_of`` built from the 837
reads, the claims it set aside, and what ``decide_claims`` returned; a fourth item, the feed rows its readers set aside, is counted in the gate's ``set_aside``, and a fifth, the rule-set files its host set aside, is named there. Every file it signs and stores goes under ``store``; the tool
cannot see inside ``decide``, so a ``decide`` that writes elsewhere breaks this rule, and a run without one is refused.
"""

import argparse
import os
import shutil
import sys
import tempfile
from pathlib import Path

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import right_rail_gate_codec as codec
from app import right_rail_gate_decide as decider
from app import right_rail_gate_ffs as ffs
from app import right_rail_gate_producer as producer
from app import right_rail_gate_signer as signer
from app import right_rail_replay_deployment as deployment
from app import right_rail_replay_diff as diff
from app import right_rail_x12_835 as r835
from app import right_rail_x12_837 as r837

INCUMBENT, GATE = "incumbent", "gate"


gate_decide = deployment.gate_decide  # the decide of a deployment that opens its own signed store (tests)


def _inside(out, home):
    """Whether ``out`` is the folder ``home`` or lies in it, by file identity along ``out``'s existing ancestors (a share, a drive or a
    link that names the same folder under another path counts)."""
    target = Path(out).resolve()
    return any(p.exists() and os.path.samefile(p, home) for p in (target, *target.parents))


def _files(path, unreadable):
    """The regular files of a file path (itself) or a folder. Every entry of a folder that is not a regular file (a subfolder, a
    dangling link) and a folder with no regular file are named in ``unreadable``: an input never yields nothing silently."""
    path = Path(path)
    if not path.is_dir():
        return [path]
    try:
        entries = sorted(path.iterdir())
    except OSError:
        unreadable.append(str(path))
        return []
    files = [p for p in entries if p.is_file()]
    unreadable.extend(str(p) for p in entries if not p.is_file())
    if not files:
        unreadable.append(str(path))
    return files


def _read(path, unreadable):
    """The file's bytes; a missing or unreadable file is named in ``unreadable`` and read as empty, which the readers refuse, so its
    side is marked incomplete and the refusal is counted in the report's ``set_aside`` (never a crash, never a silent drop)."""
    try:
        return path.read_bytes()
    except OSError:
        unreadable.append(str(path))
        return b""


def report_files(files_835, files_837, decide, out, incumbent=INCUMBENT, gate=GATE, overwrite=False, scratch=None, unreadable=None, others=None, system_map=None):
    """Write the report for these 835 and 837 paths (a file or a folder each) to ``out`` (None: no file); returns the report.
    Paths that could not be read are appended to ``unreadable``. ``files_835`` is the ``incumbent`` side (none: no such side),
    ``others`` maps the name of each further 835 side to its paths, and the ``gate`` side exists when ``files_837`` does.

    ``decide(reads, store)`` must put everything it seals under ``store``, a new empty folder made inside ``scratch`` (default: the
    system temporary folder) and removed when the run ends. Given 837 files and no ``decide`` the run is refused."""
    if files_837 and not callable(decide):
        raise ValueError("no decide path that takes a fresh store was supplied, so nothing could be replayed without sealing into a live store")
    unreadable, others = [] if unreadable is None else unreadable, others or {}
    bad_835 = []  # a deployment's decide refuses on these: an 835 that cannot be read whole could hold the newest date
    listing = {p: _files(p, bad_835) for paths in (files_835, *others.values()) for p in map(Path, paths)}
    listing.update({p: _files(p, unreadable) for p in map(Path, files_837)})
    inputs = {f.resolve() for files in listing.values() for f in files}
    folders = {p.resolve() for p in listing if p.is_dir()}
    if out is not None:
        out = Path(out)
        if not out.resolve().parent.is_dir():
            raise ValueError("the folder of the output file does not exist")
        if out.resolve() in inputs or out.resolve().parent in folders:
            raise ValueError("the output file is an input or sits in an input folder")
        home = getattr(decide, "folder", None)  # the folder of a deployment: its files are never written
        if home is not None and _inside(out, home):
            raise deployment.ReplayRefused("deployment_folder: the output file is the deployment folder or inside it")
        if out.exists() and not overwrite:
            raise ValueError("the output file exists; give --overwrite to replace it")
    named = ([(incumbent, files_835)] if files_835 else []) + sorted(others.items())
    got = [(name, [r835.read_835(_read(f, bad_835)) for p in map(Path, paths) for f in listing[p]]) for name, paths in named]
    paid = [read for _, reads in got for read in reads]  # the gate decides on what every 835 side could know
    if bad_835 and getattr(decide, "wants_835", False):
        raise deployment.ReplayRefused(f"unreadable_835: {', '.join(bad_835)}")
    unreadable.extend(bad_835)
    sides = [diff.from_835(name, reads) for name, reads in got]
    if files_837:
        reads = [r837.read_837(_read(f, unreadable)) for p in map(Path, files_837) for f in listing[p]]
        if scratch:
            Path(scratch).mkdir(parents=True, exist_ok=True)
        store = tempfile.mkdtemp(prefix="replay-store-", dir=scratch)
        try:
            sent, left, rows, *fed = decide(reads, Path(store), paid) if getattr(decide, "wants_835", False) else decide(reads, Path(store))
        finally:
            shutil.rmtree(store, ignore_errors=True)
            if Path(store).exists():  # the run's keys are never left behind, whatever else went wrong
                raise OSError("the temporary store could not be removed: " + store)
        sides.append(diff.from_decision(gate, reads, sent, rows, left, *fed))
    report = diff.diff_report(*sides, system_map=system_map)
    if out is None:
        return report
    fd, temp = tempfile.mkstemp(prefix=out.name + ".", suffix=".part", dir=out.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(diff.render(report))
        if out.exists() and not overwrite:  # a file that appeared during the run
            raise ValueError("the output file appeared during the run; give --overwrite to replace it")
        os.replace(temp, out)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    return report


def main(argv, decide=None, scratch=None):
    """``[<837 file or folder>...] [--835 <835 file or folder>...] [--side <name> <835 file or folder>...]... [--map <file> [--map-pin <128 hex>]]
    [--out <report file> [--overwrite]] [--deployment <folder> --keyset-pin <128 hex>]``; two sides at least: the ``--835`` side (named
    incumbent), each ``--side`` (an 835 side under its name) and the gate (when 837 files are given). Returns 0; 1 when the run is refused or
    fails; 3 when any input was unreadable (the report is still written). A bad command
    line raises SystemExit(2). The report goes to ``--out`` or, without it, to standard output. ``decide`` is given (it wins, for
    tests) or opens the deployment folder (app/right_rail_replay_deployment.py: public inputs only, a store of its own); with
    neither the run is refused. Argv names data, never code."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                     epilog="exit codes: 0 done; 1 refused or failed; "
                                            "3 some input was unreadable (named on stderr; the report is still written)")
    parser.add_argument("claims", nargs="*", help="an 837 file or a folder of them: adds the gate's decisions as a side")
    parser.add_argument("--835", dest="incumbent", nargs="*", default=[], help="an 835 file or a folder of them (the side named incumbent)")
    parser.add_argument("--side", action="append", nargs="+", default=[], metavar=("NAME", "PATH"), help="another 835 side: its name, then 835 files or folders")
    parser.add_argument("--map", help="the system map file: the system and owner at fault on every line (data; see app/right_rail_replay_diff.py)")
    parser.add_argument("--map-pin", help="the SHA3-512 of the system map file, 128 lowercase hex, from the state and not from the file")
    parser.add_argument("--out", help="the report file to write (default: standard output)")
    parser.add_argument("--overwrite", action="store_true", help="replace the report file if it exists")
    parser.add_argument("--deployment", help="the folder a state handed over (see app/right_rail_replay_deployment.py)")
    parser.add_argument("--keyset-pin", help="the hash of the state's genesis key set, 128 lowercase hex, from the state and not from the folder")
    args = parser.parse_args(argv)
    names = [INCUMBENT] * bool(args.incumbent) + [GATE] * bool(args.claims) + [side[0] for side in args.side]
    if bool(args.deployment) != bool(args.keyset_pin) or bool(args.map) != bool(args.map_pin):
        parser.error("--deployment and --keyset-pin go together, and so do --map and --map-pin (a map is read only against the hash the state gave)")
    if args.deployment and not args.claims:
        parser.error("--deployment decides 837 claims: give 837 files, or drop --deployment and --keyset-pin")
    if len(names) < 2 or len(set(names)) < len(names) or any(len(side) < 2 for side in args.side):
        parser.error("name two or more different sides, each with its files")
    unreadable = []
    try:
        if decide is None and args.deployment:
            decide = deployment.replay_decide(args.deployment, args.keyset_pin)
        system_map = diff.load_map(Path(args.map).read_bytes(), args.map_pin) if args.map else None
        report = report_files(args.incumbent, args.claims, decide, args.out, overwrite=args.overwrite, scratch=scratch, unreadable=unreadable,
                              others={side[0]: side[1:] for side in args.side}, system_map=system_map)
    except (OSError, ValueError, decider.GateDecideError, codec.GateCodecError, producer.GateProducerError, signer.GateSignerError) as error:
        print(f"replay_diff: {error}", file=sys.stderr)
        return 1
    for path in unreadable:
        print(f"replay_diff: could not read {path}; set aside", file=sys.stderr)
    if args.out is None:
        sys.stdout.buffer.write(diff.render(report))
    print(f"{report['differing']} of {report['compared']} keys differ, {len(unreadable)} files unreadable" + (f"; report {args.out}" if args.out else ""),
          file=sys.stderr if args.out is None else sys.stdout)
    return 3 if unreadable else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
