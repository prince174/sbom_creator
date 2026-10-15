from score_project_components import metrics


def test_equal_counts_do_not_hide_wrong_coordinate():
    result = metrics({'pkg:maven/wrong/group@1'}, {'pkg:maven/right/group@1'})
    assert result['predicted'] == result['reference'] == 1
    assert (result['tp'], result['fp'], result['fn']) == (0, 1, 1)


def test_empty_positive_metrics_are_unavailable():
    result = metrics(set(), set())
    assert result['precision'] is result['recall'] is result['f1'] is None
