from __future__ import annotations

import asyncio
import shlex
from datetime import datetime
from dataclasses import dataclass
from typing import List

from nimbus.optional.ssh_dns import SSHSessionConfig, configure_ssh_port_forward


@dataclass
class ActiveSSHSession:
    session_id: str
    job_id: int
    host_port: int
    vm_ip: str
    authorized_user: str
    expires_at: datetime
    rules: List[List[str]]


def _prepare_rule(args: List[str], delete: bool) -> List[str]:
    new_args = list(args)
    if new_args and new_args[0] == "iptables" and "-w" not in new_args[1:3]:
        new_args.insert(1, "-w")
    for idx, token in enumerate(new_args):
        if token == "-A":
            new_args[idx] = "-D" if delete else "-A"
            break
    return new_args


async def _run_command(args: List[str]) -> None:
    process = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    if process.returncode != 0:
        message = stderr.decode().strip() or stdout.decode().strip()
        raise RuntimeError(f"Command {' '.join(args)} failed: {message}")


async def apply_port_forward(config: SSHSessionConfig) -> List[List[str]]:
    commands = configure_ssh_port_forward(config)
    rules = [shlex.split(cmd) for cmd in commands]
    for rule in rules:
        await _run_command(_prepare_rule(rule, delete=False))
    return rules


async def remove_port_forward(rules: List[List[str]]) -> None:
    for rule in reversed(rules):
        try:
            await _run_command(_prepare_rule(rule, delete=True))
        except RuntimeError:
            # Ignore failures during teardown to avoid masking primary errors.
            continue
