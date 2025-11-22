import json
import os
import csv
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
    classname: str
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
            # Input.decode(m.group(2)),
            m.group(3),
        )

    # def __str__(self) -> str:
    #     return f"{self.methodid.classname}.{self.methodid.extension.name}:{self.input.encode()} -> {self.result}"

    # def encode(self) -> str:
    #     return f"{self.methodid.classname}.{self.methodid.extension.encode()} {self.input.encode()} -> {self.result}"

    def __str__(self) -> str:
        return f"{self.methodid.classname}.{self.methodid.extension.name}: '' -> {self.result}"

    def encode(self) -> str:
        return f"{self.methodid.classname}.{self.methodid.extension.encode()} '' -> {self.result}"
    # @staticmethod
    # def by_methodid(
    #     iterable: Iterable["Case"],
    # ) -> list[tuple[jvm.Absolute[jvm.MethodID], list["Case"]]]:
    #     """Given an interable of cases, group the cases by the methodid"""
    #     cases_by_id = collections.defaultdict(list)

    #     for c in iterable:
    #         cases_by_id[c.methodid].append(c)

    #     return sorted(cases_by_id.items())


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


    def parse(self) -> List[Report_Item]:
        """
        Parse analyzer results from a given file path.
        Supports: .txt, .csv
        """
        if self.extension == '.csv':
            return self._parse_csv()
        else:
            raise ValueError(f"Unsupported file format: {self.extension}")
                
                
    # Parsing the output of the PMD analyser on the OWASP java suite
    def _parse_csv(self) -> List[Report_Item]:
        """
        Reads the pmd_results.csv file.
        Header for pmd_results.csv:
        file,class,methode,beginline,endline,begincolumn,endcolumn,rule,ruleset,package,text
        """

        results : List[Report_Item] = []

        with open(self.file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)

            for row in reader:
                if not row.get("methode"):
                    continue
                
                row_file = row["file"]
                method_class = row["class"]
                package = row["package"]
                method_name = row["methode"];
                
                #LOCATION EXTRACTION MAY BE USEFUL LATER, when we use start by looking at the Report_item
                method_beginline = row["beginline"]
                method_endline = row["endline"]
                method_begincolumn = row["begincolumn"]
                method_endcolumn = row["endcolumn"]
               
                rule = row["rule"] 
                ruleset = row["ruleset"]
                
                text = row["text"]
                class_name = row["class"];
                
                full_method_str = f"{package}.{method_class}.{method_name}"
                decoded_method = jvm.AbsMethodID.decode(full_method_str)
                
                report_item = Report_Item(methodid=decoded_method, classname=class_name ,result=rule)
                print (f"FINAL REPORT ITEM {report_item}")
                results.append(report_item)
                
                # print("---- ROW DEBUG ----")
                # print(f"file           : {row_file}")
                # print(f"class          : {method_class}")
                # print(f"package        : {package}")
                # print(f"methode        : {method_name}")
                # print(f"beginline      : {method_beginline}")
                # print(f"endline        : {method_endline}")
                # print(f"begincolumn    : {method_begincolumn}")
                # print(f"endcolumn      : {method_endcolumn}")
                # print(f"rule           : {rule}")
                # print(f"ruleset        : {ruleset}")
                # print(f"text           : {text}")
                # print("--------------------\n")
                
                
                
                # print(f"METHOD FULL {method_full}")
                
                
                # print(f"METHOD NAME {method_name}")

                # method_name = jvm.AbsMethodID.decode(row["methode"])
                # class_name = jvm.AbsMethodID.decode(row["class"])
                # rule = jvm.AbsMethodID.decode(row["rule"])

                # results.append(Report_Item(methodid=method_name, classid=class_name, result=rule))

        return results
    
if __name__ == "__main__":
    file_path = "distributions_in_pmd.csv"  # Replace with your actual file path

    if not os.path.exists(file_path):
        print(f"⚠️ File not found: {file_path}")
    else:
        parser = Parser(file_path)   # ✅ create an instance of your Parser
        parsed = parser.parse()      # ✅ call the instance method
        # parsed["methoid"]
        print(parsed[0].methodid)  # ✅ access the parsed data