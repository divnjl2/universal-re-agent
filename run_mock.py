import sys
import os
import traceback
from pathlib import Path

# FORCING ENV VAR
os.environ["ANTHROPIC_API_KEY"] = "mock-api-key"

from src.main import _load_config
from src.sim.ctf_runner import CTFRunner
from src.sim.synthetic import SyntheticTask

cfg = _load_config("config.yaml")
runner = CTFRunner(cfg)
task_path = "data/training/basic_string_check.c"

try:
    if not Path(task_path).exists():
        print(f"File {task_path} does not exist!")
        sys.exit(1)
        
    print("Running eval...")
    res = runner.run_eval(task_path)
    print("Success:", res["success"])
    
except Exception as e:
    print("FAILED WITH EXCEPTION:")
    traceback.print_exc()
