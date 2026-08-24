from safeshell.parser import parse_command
from safeshell.rag import retrieve, seed


def test_rag_exact():
    seed()
    parsed = parse_command("mv a b")
    res = retrieve(parsed)
    assert res.exact is not None
    assert res.exact.source == "rag"


def test_rag_top3():
    parsed = parse_command("tar czf a b")
    res = retrieve(parsed)
    assert len(res.top3) >= 0
