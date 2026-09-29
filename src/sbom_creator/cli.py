import argparse
import json
import sys

from .pipeline import analyze, analyze_local


def main():
    parser = argparse.ArgumentParser(description="Create CycloneDX from source and container Syft SBOMs")
    sub = parser.add_subparsers(dest="command", required=True)
    remote = sub.add_parser("analyze", help="Clone a repository at an exact commit")
    remote.add_argument("--repository-url", required=True)
    remote.add_argument("--commit", required=True)
    local = sub.add_parser("analyze-local", help="Explicit local checkout / benchmark path")
    local.add_argument("--source", required=True)
    for command in (remote, local):
        command.add_argument("--image", required=True)
        command.add_argument("--output", required=True)
        command.add_argument("--mode", choices=("rules", "llm"), default="rules",
                             help="default: deterministic rules; llm is an optional explicit experimental mode")
    args = parser.parse_args()
    try:
        if args.command == "analyze":
            result = analyze(args.repository_url, args.commit, args.image, args.output, mode=args.mode)
        else:
            result = analyze_local(args.source, args.image, args.output, mode=args.mode)
    except Exception as error:  # noqa: BLE001 -- sanitize failures at the CLI boundary
        print(json.dumps({"status": "failed", "error_type": type(error).__name__,
                          "stage": getattr(error, "stage", "acquisition_or_configuration"),
                          "message": "Analysis failed; no final SBOM published"}), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
