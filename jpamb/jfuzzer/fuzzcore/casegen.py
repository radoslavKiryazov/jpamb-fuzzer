import random
import re
from typing import List, Any

from jpamb import jvm
from jpamb.jvm.base import (
    Value, Int, Boolean, Char, Array, Type
)
from jpamb.model import Input
from jpamb.jfuzzer.report_preprocess.parser import Report_Item

from pydantic import BaseModel, Field
from dotenv import load_dotenv
import os 

import jpamb


# ============================================================
# Signature Handler
# ============================================================

class SignatureHandler:
    """
    JPAMB-native signature handler using MethodID type info.
    """

    def __init__(self, abs_methodid: jvm.AbsMethodID):
        method = abs_methodid.extension

        self.param_types = list(method.params._elements)
        self.return_type = method.return_type

        print("[DEBUG] JPAMB param types:", self.param_types)

    def values_for_type(self, t: Type):
        """Return example Python values for JPAMB types."""

        if isinstance(t, Int):
            return [0, 1, -1, 42, 1337]

        if isinstance(t, Boolean):
            return [True, False]

        if isinstance(t, Char):
            return ["a", "b", "Z"]

        if isinstance(t, Array):
            elem = t.contains

            if isinstance(elem, Int):
                return [[], [1], [1, 2, 3], [-1, 0, 1]]

            if isinstance(elem, Char):
                return [["a"], ["a", "b", "c"]]

            return [[]]

        return [None]

    def generate_seeds(self):
        """Create Cartesian product of seed values."""
        from itertools import product

        if not self.param_types:
            return [()]

        value_lists = [self.values_for_type(t) for t in self.param_types]
        return list(product(*value_lists))


# Pydantic Models (LLM schema)

class LLMInputParam(BaseModel):
    type: str = Field(description="JPAMB parameter type")
    value: Any = Field(description="Concrete value for fuzzing")


class LLMCase(BaseModel):
    parameters: List[LLMInputParam]


class LLMResponse(BaseModel):
    new_cases: List[LLMCase]


# Case Generator

class CaseGenerator:
    GEN_BATCH_SIZE = 2

    def __init__(self, suite, report_item: Report_Item) -> None:
        self.target = report_item
        print(f"[DEBUG] Initializing CaseGenerator with Report_Item: {report_item}")
        self.signature = SignatureHandler(report_item.methodid)
        self.suite = suite


    def _mutate_int(self, value):
        return value + random.randint(-5, 5)
    
    def _llm_to_inputs(self, llm_json):
        """
        Convert the LLMResponse JSON into actual JPAMB Input objects.
        """
        cases = []
        print("LLM_TO_INPUTS JSON:", llm_json)
        for case_obj in llm_json:
            params = []

            for p in case_obj["parameters"]:

                if p["type"] == "int":
                    params.append(Value.int(int(p["value"])))

                elif p["type"] == "boolean":
                    params.append(Value.boolean(bool(p["value"])))

                elif p["type"] == "char":
                    params.append(Value.char(str(p["value"])))

                elif p["type"] in ("int[]", "[I"):
                    params.append(Value.array(Int(), list(p["value"])))

                elif p["type"] in ("char[]", "[C"):
                    params.append(Value.array(Char(), list(p["value"])))

                else:
                    print("[WARN] Unknown LLM type:", p)

            cases.append(Input(tuple(params)))

        return cases

    # LLM Case Generation (with previous results)

    def generate_llm_cases(self, count=GEN_BATCH_SIZE, previous_results=None):

        # Build JSON schema for the LLM
        scheme = LLMResponse.model_json_schema()

        # Extract readable method source
        print(f"[DEBUG] Extracting source for method: {self.target.methodid.classname}")
        src_path = self.suite.sourcefile(self.target.methodid.classname)
        src = src_path.read_text()
        
        bytecode_src = list(self.suite.method_opcodes(self.target.methodid))


        # Regex: extract method body from file
        pattern = rf"(?s)\b{re.escape(str(self.target.methodid))}\s*\([^)]*\)\s*\{{.*?\}}"
        match = re.search(pattern, src)

        if match:
            method_source = match.group(0)
        else:
            method_source = "METHOD_BODY_NOT_FOUND"

        previous_results = previous_results or []

        # Build the LLM prompt
        prompt = f"""
            You are a program analysis and fuzzing expert.

            We are fuzzing the method:
                {self.target.methodid}

            SOURCE CODE:
             {method_source}

            BYTECODE:
            {bytecode_src}

            PREVIOUS FUZZING RESULTS:
            {previous_results} //update to pass states of the previous items on the stack

            Your job:
            - Generate {count} *new* fuzz inputs.
            - DO NOT repeat previous inputs.
            - Prefer inputs that cover *new bytecode offsets*.
            - Try to trigger or avoid the expected behaviour: {self.target.result}.
            - Follow the JPAMB method signature exactly.

            Return ONLY JSON following this schema:
            {scheme}
            """

        response, usage = self.call_for_llm(prompt=prompt, scheme=scheme)
        
        if response is None:
            print("[ERROR] Encountered None response from LLM.")
            return [], usage
        # print("LLM Response:", response.text)
        
        print("[DEBUG] LLM raw response:", response)
        
        llm_json = response["new_cases"]
        cases = self._llm_to_inputs(llm_json)
        return cases, usage 



    def call_for_llm(self, prompt="", scheme=None):
        from google import genai
        from google.genai import types
        
        load_dotenv()  # load env vars (API key)
        api = os.getenv("API_KEY")
        
        client = genai.Client(api_key=api)

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_json_schema=scheme,
                temperature=0.2,
            ),
            contents=prompt,
        )
        
        print("[DEBUG] LLM raw response content:", response.parsed)
        print("[DEBUG] LLM raw response metadata:", response.usage_metadata)
        
        parsed = response.parsed
        usage_metadata = response.usage_metadata
        return parsed, usage_metadata


    def generate_new_cases(self, count=GEN_BATCH_SIZE) -> List[Input]:
        seeds = self.signature.generate_seeds()
        out = []

        for seed in seeds[:count]:
            jp_values = []

            for (t, v) in zip(self.signature.param_types, seed):

                if isinstance(t, Int):
                    jp_values.append(Value.int(v))

                elif isinstance(t, Boolean):
                    jp_values.append(Value.boolean(v))

                elif isinstance(t, Char):
                    jp_values.append(Value.char(v))
                elif isinstance(t, Array):
                    elem = t.contains

                    if isinstance(elem, Int):
                        jp_values.append(Value.array(Int(), v))

                    elif isinstance(elem, Char):
                        jp_values.append(Value.array(Char(), v))

                else:
                    print("[WARN] Unsupported type:", t)

            out.append(Input(tuple(jp_values)))

        return out


    def generate_mutated_cases(self, count=GEN_BATCH_SIZE):
        seeds = self.signature.generate_seeds()
        out = []

        for _ in range(count):
            base = list(random.choice(seeds))
            mutated = []

            for (t, v) in zip(self.signature.param_types, base):

                if isinstance(t, Int):
                    mutated.append(self._mutate_int(v))

                elif isinstance(t, Boolean):
                    mutated.append(not v)

                elif isinstance(t, Char):
                    mutated.append("X")

                elif isinstance(t, Array):
                    if len(v) > 0:
                        mutated.append(v + [v[-1]])
                    else:
                        mutated.append([1])

                else:
                    mutated.append(v)

            jp_values = []

            for (t, v) in zip(self.signature.param_types, mutated):

                if isinstance(t, Int):
                    jp_values.append(Value.int(v))

                elif isinstance(t, Boolean):
                    jp_values.append(Value.boolean(v))

                elif isinstance(t, Char):
                    jp_values.append(Value.char(v))

                elif isinstance(t, Array):
                    elem = t.contains
                    if isinstance(elem, Int):
                        jp_values.append(Value.array(Int(), v))
                    elif isinstance(elem, Char):
                        jp_values.append(Value.array(Char(), v))

            out.append(Input(tuple(jp_values)))

        return out



if __name__ == "__main__":

    method_id = jvm.AbsMethodID.decode("jpamb.cases.Arrays.arraySumIsLarge:([I)V")

    report_item = Report_Item(
        methodid=method_id,
        classname="Arrays",
        result="ok"
    )

    case_gen = CaseGenerator(report_item)

    print("Param types:", case_gen.signature.param_types)
    print("Seeds:", case_gen.signature.generate_seeds())

    print("\nGenerated NEW cases:")
    for case in case_gen.generate_new_cases(5):
        print(case.encode())

    print("\nGenerated MUTATED cases:")
    for case in case_gen.generate_mutated_cases(5):
        print(case.encode())
