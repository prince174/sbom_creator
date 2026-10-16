"""Same immutable post-analysis scopes as R97; no predictor access to oracle."""
from evaluate_trivy_payload_bridge import main
from run import ROOT

if __name__ == '__main__':
    main(ROOT / 'benchmarks/results/trivy-only-payload-v1')
