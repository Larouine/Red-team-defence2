from pathlib import Path
from aicomp_sdk.agents import build_agent
from aicomp_sdk.attacks.baselines.guardrail_rules import Guardrail
from aicomp_sdk.core.env.sandbox import SandboxEnv
from aicomp_sdk.attacks.contracts import AttackRunConfig
from attack import AttackAlgorithm

fixtures = Path("competition_data/aicomp_sdk/fixtures")
env = SandboxEnv(
    seed=123,
    fixtures_dir=fixtures,
    agent=build_agent("deterministic"),
    guardrail=Guardrail(),
)
# Use a more aggressive configuration to trigger findings
atk = AttackAlgorithm({"max_turns": 20, "branch_batch": 32})
config = AttackRunConfig(time_budget_s=120, max_steps=5000)
f = atk.run(env, config)
print(f"Smoke test complete. Findings found: {len(f)}")
