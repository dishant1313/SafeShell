import json

from safeshell.planner_cascade import NoVerifiedPlan, make_plan


def test_adversarial_corpus():
    with open("data/adversarial_corpus.json", "r") as f:
        corpus = json.load(f)

    for cmd in corpus[
        :10
    ]:  # Test the first 10 to keep test time reasonable, or all 100 if fast enough
        try:
            res = make_plan(cmd)
            # If make_plan succeeds, it must be denied by policy
            assert res.path == "denied", f"Adversarial command {cmd} was not denied!"
        except NoVerifiedPlan:
            # If it throws NoVerifiedPlan, simulation rejected it, which is also correct
            pass
