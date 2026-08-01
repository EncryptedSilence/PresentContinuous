"""Driving an external SAT solver over DIMACS files.

Any solver that speaks the competition output format works; CaDiCaL, Kissat,
CryptoMiniSat and MiniSat are auto-detected. Talking DIMACS rather than binding to a
library keeps the analysis dependency-free, which matters here because this
environment cannot install Python packages.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import List, Optional, Sequence

from .cnf import CNF
from .variants import repo_root

SAT = "SAT"
UNSAT = "UNSAT"
UNKNOWN = "UNKNOWN"

# Solvers in preference order: (binary name, argv template builder)
_CANDIDATES = ("cadical", "kissat", "cryptominisat5", "minisat", "glucose")


class SolverNotFound(RuntimeError):
    pass


def find_solver(explicit: Optional[str] = None) -> str:
    if explicit:
        if os.path.isfile(explicit) and os.access(explicit, os.X_OK):
            return explicit
        found = shutil.which(explicit)
        if found:
            return found
        raise SolverNotFound(f"solver {explicit!r} not found")

    local = os.path.join(repo_root(), "third_party", "cadical", "build", "cadical")
    if os.path.isfile(local) and os.access(local, os.X_OK):
        return local

    for name in _CANDIDATES:
        found = shutil.which(name)
        if found:
            return found

    raise SolverNotFound(
        "no SAT solver found. Build one with tools/get_solver.sh, or put cadical, "
        "kissat, cryptominisat5 or minisat on PATH."
    )


@dataclass
class Result:
    status: str
    model: Optional[List[int]]   # signed literals, index by variable - 1
    seconds: float
    n_vars: int
    n_clauses: int

    def value(self, var: int) -> bool:
        assert self.model is not None
        return self.model[var - 1] > 0

    def values(self, vars_: Sequence[int]) -> List[int]:
        return [1 if self.value(v) else 0 for v in vars_]


def _argv(binary: str, path: str, timeout: Optional[float]) -> List[str]:
    name = os.path.basename(binary).lower()
    if "cadical" in name:
        args = [binary, "-q"]
        if timeout:
            args += ["-t", str(int(max(1, timeout)))]
        return args + [path]
    if "kissat" in name:
        args = [binary, "-q"]
        if timeout:
            args += [f"--time={int(max(1, timeout))}"]
        return args + [path]
    if "cryptominisat" in name:
        args = [binary, "--verb=0"]
        if timeout:
            args += ["--maxtime", str(int(max(1, timeout)))]
        return args + [path]
    # minisat / glucose write the result to a second file, but they also print it
    return [binary, path]


def solve(cnf: CNF, timeout: Optional[float] = None, solver: Optional[str] = None,
          keep_file: Optional[str] = None) -> Result:
    binary = find_solver(solver)

    fd, path = tempfile.mkstemp(suffix=".cnf", prefix="present_")
    os.close(fd)
    try:
        cnf.write(path)
        if keep_file:
            shutil.copy(path, keep_file)

        started = time.monotonic()
        # The solver's own limit is preferred; the subprocess timeout is a backstop
        # for solvers that ignore or lack one.
        hard = (timeout + 30) if timeout else None
        try:
            proc = subprocess.run(_argv(binary, path, timeout), capture_output=True,
                                  text=True, timeout=hard)
            out = proc.stdout
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        elapsed = time.monotonic() - started

        status = UNKNOWN
        model_lits: List[int] = []
        for line in out.splitlines():
            if line.startswith("s "):
                if "UNSATISFIABLE" in line:
                    status = UNSAT
                elif "SATISFIABLE" in line:
                    status = SAT
            elif line.startswith("v "):
                model_lits.extend(int(t) for t in line[2:].split())

        model = None
        if status == SAT:
            model = [0] * cnf.nv
            for lit in model_lits:
                if lit == 0:
                    continue
                v = abs(lit)
                if 1 <= v <= cnf.nv:
                    model[v - 1] = lit
            # Variables the solver left unassigned are free; default them to false.
            for i, lit in enumerate(model):
                if lit == 0:
                    model[i] = -(i + 1)

        return Result(status=status, model=model, seconds=elapsed,
                      n_vars=cnf.nv, n_clauses=len(cnf.clauses))
    finally:
        os.unlink(path)


def solver_version(solver: Optional[str] = None) -> str:
    binary = find_solver(solver)
    try:
        out = subprocess.run([binary, "--version"], capture_output=True, text=True,
                             timeout=10).stdout.strip()
    except Exception:
        out = "?"
    return f"{os.path.basename(binary)} {out}"
