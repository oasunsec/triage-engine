"""Reproducible mixed-evidence demo: one EVTX file plus synthetic artifacts.

The EVTX input is supplied by the caller, by default the public
EVTX-ATTACK-SAMPLES Sysmon scheduled-task sample. The raw task definition, persistence and
Prefetch records are synthetic and labelled as such. Nothing is collected from
this host. Output stays under runtime/output/ unless --output-dir is given.

    python scripts/demo_cross_source_case.py
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from triage_engine import service  # noqa: E402
from triage_engine.artifact_packager import pack_artifacts  # noqa: E402
from triage_engine.product import export_case_bundle, verify_case_bundle  # noqa: E402

DEFAULT_EVTX = ROOT / "repo_cache" / "sbousseaden_EVTX-ATTACK-SAMPLES" / "Privilege Escalation" / \
    "sysmon_1_11_exec_as_system_via_schedtask.evtx"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--evtx", type=Path, default=DEFAULT_EVTX)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "runtime" / "output" / "dfir-correlation-demo")
    args = parser.parse_args()
    if not args.evtx.is_file():
        print(f"EVTX sample not found: {args.evtx}", file=sys.stderr)
        return 2
    out = args.output_dir.resolve()
    if out.exists():
        shutil.rmtree(out)
    sources = out / "sources"
    sources.mkdir(parents=True)
    persistence = sources / "synthetic-persistence.json"
    persistence.write_text(json.dumps({"schema_version": "1.0", "records": [
        {"kind": "scheduled_task", "name": "BenignUpdater", "location": "\\",
         "command": r'"C:\Program Files\Example\updater.exe" /check'},
        {"kind": "service", "name": "ExampleSvc", "location": "Win32_Service",
         "command": r"%SystemRoot%\System32\svchost.exe -k example"},
    ]}, indent=1), encoding="utf-8")
    # Raw Task Scheduler definition, as stored under System32\Tasks (UTF-16 with BOM).
    task = sources / "elevator"
    task.write_bytes(b"\xff\xfe" + (
        '<?xml version="1.0" encoding="UTF-16"?>\n<Task version="1.2" '
        'xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><RegistrationInfo><URI>\\elevator</URI>'
        '<Description>Synthetic demo task</Description></RegistrationInfo><Principals><Principal id="Author">'
        '<UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>'
        r'<Actions Context="Author"><Exec><Command>c:\Windows\System32\cmd.exe</Command></Exec></Actions></Task>'
    ).encode("utf-16-le"))
    prefetch = sources / "synthetic-prefetch.jsonl"
    prefetch.write_text(json.dumps({
        "SourceFilename": r"C:\Windows\Prefetch\CMD.EXE-4A81B364.pf", "ExecutableName": "CMD.EXE",
        "RunCount": "3", "Version": "17", "Hash": "4A81B364",
        "LastRun": "2019-05-12T00:32:40.0000000+00:00", "ParsingError": False}) + "\n", encoding="utf-8")
    bundle = pack_artifacts(out / "bundle", host="IEWIN7", observed_at="2019-05-12T01:00:00Z",
                            persistence_records=[persistence], pecmd_jsonl=[prefetch], pecmd_version="SYNTHETIC-DEMO",
                            scheduled_task_xml=[task])
    result = service.run_investigation(service.InvestigationRequest(
        str(args.evtx), artifact_bundle=str(bundle), case_name="cross-source-demo", cases_dir=str(out / "cases")))
    case = Path(result.case_path)
    links = json.loads((case / "evidence_relationships.json").read_text(encoding="utf-8"))
    findings = json.loads((case / "findings.json").read_text(encoding="utf-8"))
    archive = export_case_bundle(str(case), str(out / "cross-source-demo.zip"))
    print(f"case: {case}")
    print(f"findings: {[f['title'] for f in findings['findings']]}")
    print(f"incidents: {[i['title'] for i in findings['incidents']]}")
    print(f"unresolved commands: {links['summary']['coverage']['families']['persistence_configuration']['unresolved_command_paths']}")
    for link in links["relationships"]:
        claims = [claim["class"] for claim in link["inferred_claims"]]
        print(f"link: {link['link_class']} | {link['rule']['name']} | {link['source']['process']} -> "
              f"{link['target']['artifact_kind']} record {link['target']['source_record']} | inferred: {claims}")
    print(f"report: {result.artifacts['report']}")
    print(f"zip verified: {verify_case_bundle(archive)['valid']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
