from datetime import UTC, datetime

from retry_trivy_pom_metadata import backoff_elapsed, latest_backoff


def test_network_backoff_boundary_is_not_rounded_down():
    policy = {'not_before_utc': '2026-10-15T21:28:21Z'}
    assert not backoff_elapsed(policy, datetime(2026, 10, 15, 21, 28, 20, 999999, tzinfo=UTC))
    assert backoff_elapsed(policy, datetime(2026, 10, 15, 21, 28, 21, tzinfo=UTC))


def test_backoff_compares_instants_with_explicit_offset():
    policy = {'not_before_utc': '2026-10-16T02:28:21+05:00'}
    assert not backoff_elapsed(policy, datetime(2026, 10, 15, 21, 28, 20, tzinfo=UTC))
    assert backoff_elapsed(policy, datetime(2026, 10, 15, 21, 28, 21, tzinfo=UTC))


def test_renewed_backoff_supersedes_expired_attempt():
    first = {'not_before_utc': '2026-10-15T21:28:21Z'}
    renewed = {'not_before_utc': '2026-10-15T21:58:33Z'}
    now = datetime(2026, 10, 15, 21, 30, tzinfo=UTC)
    assert backoff_elapsed(first, now)
    assert not backoff_elapsed(latest_backoff([renewed, first]), now)
