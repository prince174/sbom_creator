import argparse
import json
import sys
from pathlib import Path

from .evaluation import LIMIT, compare, validate_reference
from .pipeline import analyze, analyze_local, error_fields


def main():
    parser = argparse.ArgumentParser(description="Create CycloneDX from source and container Syft SBOMs")
    sub = parser.add_subparsers(dest="command", required=True)
    remote = sub.add_parser("analyze", help="Analyze an image, optionally with repository + exact commit")
    remote.add_argument("--repository-url")
    remote.add_argument("--commit")
    local = sub.add_parser("analyze-local", help="Explicit local checkout / benchmark path")
    local.add_argument("--source", required=True)
    for command in (remote, local):
        command.add_argument("--image", required=True)
        command.add_argument("--output", required=True)
        command.add_argument('--run-mode', choices=('production', 'verification'), default='production')
        command.add_argument('--reference-sbom')
        command.add_argument('--reference-scope', choices=('runtime', 'build', 'unknown'), default='unknown')
        command.add_argument("--mode", choices=("rules", "llm"), default="rules",
                             help="default: deterministic rules; llm is an optional explicit experimental mode")
    args = parser.parse_args()
    stage = 'acquisition_or_configuration'
    try:
        reference = None
        if args.run_mode == 'production' and args.reference_sbom:
            raise ValueError('Reference requires verification mode')
        if args.run_mode == 'verification':
            if not args.reference_sbom or Path(args.reference_sbom).stat().st_size > LIMIT:
                raise ValueError('Missing or oversized reference')
            reference = validate_reference(json.loads(Path(args.reference_sbom).read_bytes()))
        if args.command == "analyze":
            result = analyze(args.repository_url, args.commit, args.image, args.output, mode=args.mode)
        else:
            result = analyze_local(args.source, args.image, args.output, mode=args.mode)
        if reference is not None:
            stage = 'verification'
            evaluation = compare(args.output, reference, args.reference_scope)
            from .pipeline import write_json
            write_json(Path(args.output) / 'evaluation.json', evaluation)
            result = dict(result, evaluation=evaluation)
    except Exception as error:  # noqa: BLE001 -- sanitize failures at the CLI boundary
        print(json.dumps({"status": "failed", **error_fields(error, stage),
                          "message": "Analysis failed; output blocked"}), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
