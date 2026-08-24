from safeshell.parser import parse_bundle


def test_parse_bundle():
    script = """
# This is a comment
sudo systemctl stop nginx
rm -rf /var/log/nginx/*
sudo systemctl start nginx
"""
    commands = parse_bundle(script)
    assert len(commands) == 3
    assert commands[0].executable == "systemctl"
    assert commands[1].executable == "rm"
    assert commands[2].executable == "systemctl"
