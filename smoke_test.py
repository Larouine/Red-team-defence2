from pathlib import Path
from aicomp_sdk.agents import build_agent
from aicomp_sdk.attacks.baselines.guardrail_rules import Guardrail
from aicomp_sdk.core.env.sandbox import SandboxEnv
from aicomp_sdk.attacks.contracts import AttackRunConfig
from attack import AttackAlgorithm
import time

fixtures = Path("competition_data/aicomp_sdk/fixtures")
env = SandboxEnv(
    seed=123,
    fixtures_dir=fixtures,
    agent=build_agent("deterministic"),
    guardrail=Guardrail(),
)
atk = AttackAlgorithm({"max_turns": 20, "branch_batch": 32})
# Running for 3 minutes for a solid test
config = AttackRunConfig(time_budget_s=180, max_steps=10000)
start_time = time.time()
f = atk.run(env, config)
duration = time.time() - start_time
print(f"Final Smoke Test complete.")
print(f"Duration: {duration:.2f}s")
print(f"Findings found: {len(f)}")
