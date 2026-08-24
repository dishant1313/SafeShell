import os
import shlex

from safeshell.schemas import ParsedCommand


def tokenize(cmd_str: str) -> list[str]:
    try:
        return shlex.split(cmd_str)
    except ValueError:
        return []


def split_segments(tokens: list[str]) -> list[list[str]]:
    segments = []
    current = []
    for token in tokens:
        if token in ("|", "&&", "||", ";"):
            if current:
                segments.append(current)
            current = []
        else:
            current.append(token)
    if current:
        segments.append(current)
    return segments


def resolve_paths(args: list[str]) -> list[str]:
    resolved = []
    for arg in args:
        if "/" in arg or arg == "." or arg.startswith("~") or os.path.exists(arg):
            resolved.append(arg)
    return resolved


def infer_effects(executable: str, flags: list[str], args: list[str], resolved: list[str]) -> dict:
    effects = {
        "creates": [],
        "deletes": [],
        "modifies": [],
        "permissions": [],
        "service_state": [],
        "network_egress": [],
        "process_spawn": [],
    }

    if executable in ("rm", "unlink"):
        effects["deletes"].extend(resolved)
    elif executable in ("touch", "mkdir"):
        effects["creates"].extend(resolved)
    elif executable in ("chmod", "chown"):
        effects["permissions"].extend(resolved)
    elif executable in ("mv", "cp"):
        if len(resolved) > 1:
            effects["modifies"].extend(resolved[:-1])
            effects["creates"].append(resolved[-1])
        else:
            effects["modifies"].extend(resolved)
    elif executable == "systemctl":
        if args and args[0] in ("start", "stop", "restart", "enable", "disable"):
            effects["service_state"].extend(args[1:])
    elif executable in ("curl", "wget"):
        effects["network_egress"].extend(args)
    else:
        effects["process_spawn"].append(executable)

    return effects


def parse_segment(segment: list[str]) -> ParsedCommand:
    if not segment:
        return ParsedCommand(executable="")

    privilege_escalation = False
    idx = 0

    if segment[idx] == "sudo":
        privilege_escalation = True
        idx += 1

    if idx >= len(segment):
        return ParsedCommand(executable="sudo", privilege_escalation=True)

    executable = segment[idx]
    idx += 1

    flags = []
    arguments = []
    for token in segment[idx:]:
        if token.startswith("-"):
            flags.append(token)
        else:
            arguments.append(token)

    resolved = resolve_paths(arguments)
    effects = infer_effects(executable, flags, arguments, resolved)

    return ParsedCommand(
        executable=executable,
        flags=flags,
        arguments=arguments,
        resolved_paths=resolved,
        privilege_escalation=privilege_escalation,
        effect_graph=effects,
    )


def parse_command(cmd_str: str) -> ParsedCommand:
    tokens = tokenize(cmd_str)
    if not tokens:
        return ParsedCommand(executable="")

    segments = split_segments(tokens)

    if not segments:
        return ParsedCommand(executable="")

    parsed_segments = [parse_segment(seg) for seg in segments]

    base = parsed_segments[0]

    pipes = []
    for i, token in enumerate(tokens):
        if token == "|":
            if i + 1 < len(tokens):
                pipes.append(tokens[i + 1])

    for parsed in parsed_segments[1:]:
        base.resolved_paths.extend(parsed.resolved_paths)
        base.privilege_escalation = base.privilege_escalation or parsed.privilege_escalation

        for key, val in parsed.effect_graph.items():
            if isinstance(val, list):
                base.effect_graph[key].extend(val)

    base.pipes = pipes
    # Set bundle_steps to 1 by default
    base.bundle_steps = 1
    return base


def parse_bundle(script: str) -> list[ParsedCommand]:
    commands = []
    for line in script.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            commands.append(parse_command(line))
    return commands
