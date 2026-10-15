from unittest.mock import patch

from check_jar_content_budget import MAX_TOTAL_READ, BudgetFiles

from sbom_creator import payload


def reader(size, used=0):
    instance = object.__new__(BudgetFiles)
    instance.files = {'/app/test.jar': {'metadata': {'size': size}}}
    instance.stats = {'read_bytes': used, 'read_calls': 0, 'budget_rejections': 0}
    return instance


def test_aggregate_budget_rejects_before_layer_read():
    instance = reader(2, MAX_TOTAL_READ-1)
    with patch.object(payload.ImageFiles, 'read') as original:
        assert instance.read('/app/test.jar') is None
        original.assert_not_called()
    assert instance.stats['budget_rejections'] == 1


def test_per_file_budget_cannot_be_overridden_by_caller():
    instance = reader(payload.MAX_READ+1)
    with patch.object(payload.ImageFiles, 'read') as original:
        assert instance.read('/app/test.jar', payload.MAX_READ*2) is None
        original.assert_not_called()


def test_exact_remaining_budget_is_accepted_once():
    instance = reader(2, MAX_TOTAL_READ-2)
    with patch.object(payload.ImageFiles, 'read', return_value=b'ab') as original:
        assert instance.read('/app/test.jar') == b'ab'
        assert instance.read('/app/test.jar') is None
        assert original.call_count == 1
    assert instance.stats == {'read_bytes': MAX_TOTAL_READ, 'read_calls': 1, 'budget_rejections': 1}
