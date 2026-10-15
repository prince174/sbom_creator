"""Build-only checkpoint for a new Rust pair; not a completed reference receipt."""
import json

from run import ROOT, run_command


def main():
    work = ROOT / 'benchmarks/.work/paired-fd-v1'
    work.mkdir(parents=True, exist_ok=True)
    project = next(p for p in json.loads((ROOT / 'benchmarks/manifest.json').read_bytes())['repositories'] if p['id'] == 'rust-fd')
    source = work / 'src'
    if not source.exists():
        run_command(['git', 'clone', '--no-hardlinks', '--no-checkout', str(ROOT / 'benchmarks/.work/rust-fd/src'), str(source)], work / 'clone.log')
        run_command(['git', '-c', 'core.autocrlf=false', 'checkout', '--detach', project['commit']], work / 'checkout.log', cwd=source)
    recipe = (ROOT / 'benchmarks/references/build-v1/rust-fd/Dockerfile').read_text()
    recipe = recipe.replace('rust:1.85.1-bookworm', 'rust:1.85.1-bookworm@sha256:e51d0265072d2d9d5d320f6a44dde6b9ef13653b035098febd68cce8fa7c0bc4')
    recipe = recipe[:recipe.index('FROM scratch AS export')]
    recipe = recipe.replace('cargo auditable build --locked --bins', 'cargo auditable build --locked --bins --target x86_64-unknown-linux-gnu')
    recipe = recipe.replace('find target/debug', 'find target/x86_64-unknown-linux-gnu/debug')
    recipe += ('RUN cargo metadata --locked --format-version 1 --filter-platform x86_64-unknown-linux-gnu > /reference/filtered.json && '
               'cargo cyclonedx --help > /reference/generator-help.txt && rustc -Vv > /reference/rustc.txt && '
               'cargo -V > /reference/cargo.txt && cargo cyclonedx --version > /reference/generator-version.txt\n'
               'FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS runtime\n'
               'COPY --from=build /out/ /app/\nUSER 65532:65532\nCMD ["/app/fd", "--help"]\n')
    if (work / 'Dockerfile').exists() and (work / 'Dockerfile').read_text() != recipe:
        raise ValueError('Checkpoint recipe changed; choose a new workspace')
    (work / 'Dockerfile').write_text(recipe, encoding='utf-8')
    (work / '.dockerignore').write_text('**\n!Dockerfile\n!src/\n!src/**\n', encoding='utf-8')
    for stage in ('build', 'runtime'):
        if (work / (stage + '.id')).exists():
            continue
        run_command(['docker', 'build', '--platform=linux/amd64', '--target', stage,
                     '--iidfile', str(work / (stage + '.id')), str(work)], work / (stage + '.log'), timeout=1800)
    print('Rust pair build checkpoint ready; export/binding/schema validation still required')


if __name__ == '__main__':
    main()
