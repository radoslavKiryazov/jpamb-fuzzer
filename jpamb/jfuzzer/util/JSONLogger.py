import json
import time
from pathlib import Path
from datetime import datetime


class JSONFuzzerLogger:
    """
    Writes per-alarm fuzzing results using the agreed JSON template.
    """

    def __init__(self, base_dir="logs"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _get_output_path(self, methodid):
        safe_name = str(methodid).replace("/", "_").replace(":", "_")
        return self.base_dir / f"{safe_name}.json"

    def start_log(self, alarm_item, config):
        """
        Creates the initial structure for a fuzzing log.
        """
        self.start_time = time.time()
        path = self._get_output_path(alarm_item.methodid)

        print("JSONLOGGER START LOG")

        self.data = {
            "fuzz_target": {
                "methodid": str(alarm_item.methodid),
                "original_alarm": alarm_item.result,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            },

            "config": config,
            "results": [],
            "summary": {
                "total_rounds_executed": 0,
                "target_hits": 0,
                "unique_new_failures": 0,
                "runtime_seconds": 0
            }
        }

        self._write(path)

    def log_round(self, round_index, cases, target_hit):
        """
        Add a full round of cases into the JSON structure.
        """
        self.data["results"].append({
            "round": round_index,
            "cases": cases,
            "target_hit": target_hit
        })

        self.data["summary"]["total_rounds_executed"] += 1
        if target_hit:
            self.data["summary"]["target_hits"] += 1

        # TODO: count distinct new failures later
        self.data["summary"]["unique_new_failures"] = 0

        path = self._get_output_path(self.data["fuzz_target"]["methodid"])
        self._write(path)

    def finish(self):
        """
        Finalize summary and persist the final version.
        """
        self.data["summary"]["runtime_seconds"] = time.time() - self.start_time

        path = self._get_output_path(self.data["fuzz_target"]["methodid"])
        self._write(path)

    def _write(self, path: Path):
        with open(path, "w") as f:
            json.dump(self.data, f, indent=2)
        print(f"[LOGGER] Saved fuzzing log to {path.absolute()}")
