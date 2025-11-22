from jpamb.logger import log
from enum import Enum


class Oracle_Output(Enum):
    TARGET_HIT = "TARGET_HIT"
    NEW_ALARM = "NEW_ALARM"
    FIXED = "FIXED"
    OK = "OK"
    
class Oracle:
    """
    Oracle for classifying fuzzing outcomes.

    - Target reproduced: same alarm as original
    - New alarm: different alarm, but not ok
    - Alarm fixed: original alarm was not reproduced (got ok)
    """

    def __init__(self, expected_alarm: str):
        self.expected_alarm = expected_alarm.lower()

    def classify(self, current_alarm: str) -> str:
        """
        Classify the current fuzzing result.

        Returns one of:
            - "TARGET_HIT"
            - "NEW_ALARM"
            - "FIXED"
            - "OK"      (when expected alarm was 'ok' and we also get ok)
        """

        curr = current_alarm.lower()
        expected = self.expected_alarm

        # Expected alarm is reproduced exactly
        if curr == expected and curr != "ok":
            log.info(f"[ORACLE] TARGET HIT — reproduced expected alarm '{expected}'.")
            return Oracle_Output.TARGET_HIT.value

        # A new alarm appears (and it was not expected)
        if curr != "ok" and curr != expected:
            log.warning(f"[ORACLE] NEW ALARM — expected '{expected}', got '{curr}'.")
            return Oracle_Output.NEW_ALARM.value

        log.info("[ORACLE] OK — no alarm expected and none encountered.")
        return Oracle_Output.OK.value
