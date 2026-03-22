from app.axe_mapper import map_axe_results


def test_maps_violation_to_schema():
    result = {
        "violations": [
            {
                "id": "image-alt",
                "description": "Images must have alternate text",
                "impact": "serious",
                "tags": ["wcag111", "wcag2a"],
                "nodes": [{"target": ["img.hero"], "failureSummary": "Fix the missing alt text."}],
            }
        ],
        "passes": [],
        "incomplete": [],
    }

    violations, _, _ = map_axe_results(result, include_remediation=True)

    assert violations[0].rule_id == "image-alt"
    assert violations[0].impact == "serious"
    assert violations[0].selector == "img.hero"
    assert violations[0].wcag_sc == "1.1.1"
    assert violations[0].remediation == "Fix the missing alt text."


def test_maps_passes_and_incomplete_confidence():
    result = {
        "violations": [],
        "passes": [{"id": "html-has-lang", "description": "lang set", "impact": "moderate", "tags": ["wcag311"]}],
        "incomplete": [{"id": "color-contrast", "description": "contrast review", "impact": "serious", "tags": ["wcag143"]}],
    }

    _, passes, incomplete = map_axe_results(result, include_remediation=False)

    assert passes[0].confidence == 0.95
    assert passes[0].wcag_sc == "3.1.1"
    assert 0.4 <= incomplete[0].confidence <= 0.6
    assert incomplete[0].wcag_sc == "1.4.3"
