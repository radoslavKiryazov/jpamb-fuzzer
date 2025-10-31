import json
import os
import csv
from typing import List, Dict, Any
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
class Parser:
 def __init__(self, file_path: str):
    self.file_path = file_path
    self.extension = os.path.splitext(file_path)[1].lower()

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

#TODO FIX THIS TO MATCH JSON
 def _parse_csv(self) -> List[Dict[str, Any]]:
    """
    Parse .csv formatted results.
    """
    results = []
    errors = {}
    with open(self.file_path, 'r', encoding="utf-8") as f:
        reader = csv.DictReader(f)
        method_name = "";
        
        next(reader)  # Skip header row if necessary
        
        for row in reader:
            print('Row:', row)
            if not (row):
                continue
            
            try: 
                method_name = row["method"];
            
                errors = {
                    "infinite loop": int(row["*"]),
                    "assertion error": int(row["assertion error"]),
                    "divide by zero": int(row["divide by zero"]),
                    "null pointer": int(row["null pointer"]),
                    "ok": int(row["ok"]),
                    "out of bounds": int(row["out of bounds"]),
                    }
            except Exception as e:
                print(f"Error printing row: {e}")
            if method_name == "":
                continue
            results.append({
                "method": method_name,
                "errors": errors
            })
            print(f"Parsed CSV result: {row}")
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