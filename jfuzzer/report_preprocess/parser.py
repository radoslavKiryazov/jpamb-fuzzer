import json
import os
import csv
import jpamb
import re
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass
from collections.abc import Iterable
from jpamb import jvm


"""
Expected format:
{
"method": "jpamb.cases.Arrays.arrayOutOfBounds:()V",
"errors": {
 "infinite loop": 0,
 "assertion error": 1,
 "divide by zero": 0,
 "null pointer": 0,
 "ok": 0,
 "out of bounds: 0,
 }    
}
"""


CASE_RE = re.compile(r"([^ ]*) +(\([^)]*\)) -> (.*)")


@dataclass(frozen=True, order=True)
class Report_Item:
    """
    A 'Case' is an absolute method id, an input, and the expected result.
    """

    methodid: jvm.Absolute[jvm.MethodID]
    # input: Input
    result: str

    @staticmethod
    def match(line) -> re.Match:
        if not (m := CASE_RE.match(line)):
            raise ValueError(f"Unexpected line: {line!r}")
        return m

    @staticmethod
    def decode(line):
        m = Case.match(line)
        return Case(
            jvm.AbsMethodID.decode(m.group(1)),
            Input.decode(m.group(2)),
            m.group(3),
        )

    def __str__(self) -> str:
        return f"{self.methodid.classname}.{self.methodid.extension.name}:{self.input.encode()} -> {self.result}"

    def encode(self) -> str:
        return f"{self.methodid.classname}.{self.methodid.extension.encode()} {self.input.encode()} -> {self.result}"

    @staticmethod
    def by_methodid(
        iterable: Iterable["Case"],
    ) -> list[tuple[jvm.Absolute[jvm.MethodID], list["Case"]]]:
        """Given an interable of cases, group the cases by the methodid"""
        cases_by_id = collections.defaultdict(list)

        for c in iterable:
            cases_by_id[c.methodid].append(c)

        return sorted(cases_by_id.items())


class Parser:
    # def __new__(cls, workfolder: Path | None = None):
    #     workfolder = workfolder or Path.cwd()
    #     if workfolder not in cls._instances:
    #         cls._instances[workfolder] = super().__new__(cls)
    #     return cls._instances[workfolder]


    def __init__(self, file_path: str, workfolder: Path | None = None):
        self.file_path = file_path
        self.extension = os.path.splitext(file_path)[1].lower()

        workfolder = workfolder or Path.cwd()
        assert workfolder.is_absolute(), f"Assuming that {workfolder} is absolute."
        self.workfolder = workfolder
        # self.invalidate_cache()


    # def invalidate_cache(self):
    #     """Invalidate the case, and require a recomputation of the cached values."""
    #     self._cases = None


    @property
    def stats_folder(self) -> Path:
        """The folder to place the statistics about the repository"""
        return self.workfolder / "stats"


    @property
    def case_file(self) -> Path:
        return self.stats_folder / "cases.txt"


    @property
    def report_file(self) -> Path:
        return self.stats_folder / "report.csv"


    @property
    def cases(self) -> tuple[Report_Item, ...]:
        if self._cases is None:
            with open(self.case_file) as f:
                self._cases = tuple(Case.decode(line) for line in f)
        return self._cases


    def parse(self) -> List[Dict[str, Any]]:
        """
        Parse analyzer results from a given file path.
        Supports: .txt, .csv
        """
        if self.extension == '.txt':
            return self._parse_txt()
        elif self.extension == '.csv':
            return self._parse_csv()
        else:
            raise ValueError(f"Unsupported file format: {self.extension}")
                

    #TODO CHANGE TO MATCH TXT
    def _parse_txt(self) -> List[Dict[str, Any]]:
        """
        Parse .txt formatted results.
        """
        results = []
        pass
        return results


    def _parse_csv(self) -> List[Report_Item]:
        """
        CSV expected format (example):

        method,* ,assertion error,divide by zero,null pointer,ok,out of bounds
        jpamb.cases.Arrays.arrayOutOfBounds:()V,0,1,0,0,0,0
        """

        results: List[Report_Item] = []

        with open(self.file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)

            for row in reader:
                if not row.get("method"):
                    continue

                # methodid = jvm.AbsMethodID.decode(row["method"])
                method_name = row["method"];
                  # count occurrences
                error_counts = {
                    # "infinite loop": int(row["*"]),
                    "assertion error": int(row["assertion error"]),
                    "divide by zero": int(row["divide by zero"]),
                    "null pointer": int(row["null pointer"]),
                    "ok": int(row["ok"]),
                    "out of bounds": int(row["out of bounds"]),
                }   
                
                # choose the one with the largest count
                selected_error = max(error_counts, key=error_counts.get)

                results.append({"method_name": method_name, "result": selected_error})

        return results


    #TODO FIX THIS TO MATCH JSON
    def _parse_json(path:str) -> List[Dict[str, Any]]:
        """
        Parse .json formatted results.
        """
        data = []
        pass
        return data
    
    
if __name__ == "__main__":
    file_path = "distributions.csv"

    if not os.path.exists(file_path):
        print(f"⚠️ File not found: {file_path}")
    else:
        parser = Parser(file_path)   # ✅ create an instance of your Parser
        parsed = parser.parse()      # ✅ call the instance method
        print("\n✅ Parsed Results (JSON formatted):")
        print(json.dumps(parsed, indent=4))