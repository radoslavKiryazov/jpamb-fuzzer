import random
import re
import json
import os
from typing import List, Any, Tuple, Dict

from dotenv import load_dotenv
from pydantic import BaseModel, Field

from jpamb import jvm
from jpamb.jvm.base import Value, Int, Boolean, Char, Array, Type
from jpamb.model import Input
from jpamb.jfuzzer.report_preprocess.parser import Report_Item


# ============================================================
# Signature Handler
# ============================================================

class SignatureHandler:
    """
    JPAMB-native signature handler using MethodID type info.
    """

    def __init__(self, abs_methodid: jvm.AbsMethodID):
        method = abs_methodid.extension

        # Parameter and return types from JPAMB's MethodID
        self.param_types: List[Type] = list(method.params._elements)
        self.return_type: Type = method.return_type

        print("[DEBUG] JPAMB param types:", self.param_types)

    def values_for_type(self, t: Type) -> List[Any]:
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

        # Fallback – should not really happen for JPAMB cases
        return [None]

    def generate_seeds(self) -> List[Tuple[Any, ...]]:
        """Create Cartesian product of seed values."""
        from itertools import product

        if not self.param_types:
            return [()]

        value_lists = [self.values_for_type(t) for t in self.param_types]
        return list(product(*value_lists))

    def build_previous_state_summary(
        self,
        previous_results: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Condense previous_results into a compact, LLM-friendly history.

        expected structure per entry in previous_results:
        {
          "method": str,
          "round": int,
          "input": str,
          "output": str,
          "classification": str,
          # optionally (if you add them later):
          # "opcodes": [...],
          # "stack_snapshot": [...]
        }
        """
        history: List[Dict[str, Any]] = []

        for entry in previous_results:
            history.append(
                {
                    "round": entry.get("round"),
                    "input": entry.get("input"),
                    "output": entry.get("output"),
                    "classification": entry.get("classification"),
                    "opcodes": entry.get("opcodes"),          # optional / maybe None
                    "stack_snapshot": entry.get("stack_snapshot"),  # optional / maybe None
                }
            )

        return history


# ============================================================
# Pydantic Models (LLM schema)
# ============================================================

class LLMInputParam(BaseModel):
    type: str = Field(description="JPAMB parameter type, e.g., 'int', 'int[]', '[I', 'boolean', 'char', 'char[]', '[C'")
    value: Any = Field(description="Concrete value for fuzzing matching the given JPAMB type")


class LLMCase(BaseModel):
    parameters: List[LLMInputParam]


class LLMResponse(BaseModel):
    new_cases: List[LLMCase]


# ============================================================
# Case Generator
# ============================================================

class CaseGenerator:
    GEN_BATCH_SIZE = 2

    def __init__(self, suite, report_item: Report_Item) -> None:
        """
        :param suite: jpamb.model.Suite instance (from cli)
        :param report_item: alarm/report item with .methodid and .result
        """
        self.target: Report_Item = report_item
        self.signature = SignatureHandler(report_item.methodid)
        self.suite = suite

        print(f"[DEBUG] Initializing CaseGenerator with Report_Item: {report_item}")

    # --------------------------------------------------------
    # Basic seed + mutation (non-LLM fallback)
    # --------------------------------------------------------

    def _mutate_int(self, value: int) -> int:
        return value + random.randint(-5, 5)

    def generate_new_cases(self, count: int = GEN_BATCH_SIZE) -> List[Input]:
        """
        Pure signature-based seed generation (no LLM).
        """
        seeds = self.signature.generate_seeds()
        out: List[Input] = []

        for seed in seeds[:count]:
            jp_values: List[Value] = []

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
                    print("[WARN] Unsupported type in generate_new_cases:", t)

            out.append(Input(tuple(jp_values)))

        return out

    def generate_mutated_cases(self, count: int = GEN_BATCH_SIZE) -> List[Input]:
        """
        Mutation based on seed cases.
        """
        seeds = self.signature.generate_seeds()
        out: List[Input] = []

        for _ in range(count):
            base = list(random.choice(seeds))
            mutated: List[Any] = []

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

            jp_values: List[Value] = []

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

    # --------------------------------------------------------
    # LLM-based case generation
    # --------------------------------------------------------

    def _llm_to_inputs(self, llm_cases: List[Dict[str, Any]]) -> List[Input]:
        """
        Convert the 'new_cases' portion of the LLM JSON into JPAMB Input objects.

        Expects something like:
        {
          "new_cases": [
            {
              "parameters": [
                {"type": "int", "value": 42},
                {"type": "[I", "value": [1, 2, 3]},
                ...
              ]
            },
            ...
          ]
        }
        """
        cases: List[Input] = []

        for case_obj in llm_cases:
            params = []

            for p in case_obj.get("parameters", []):
                p_type = p.get("type")
                p_val = p.get("value")

                if p_type == "int":
                    params.append(Value.int(int(p_val)))

                elif p_type == "boolean":
                    # Ensure bool – in case it's "true"/"false"/1/0
                    if isinstance(p_val, str):
                        params.append(Value.boolean(p_val.lower() == "true"))
                    else:
                        params.append(Value.boolean(bool(p_val)))

                elif p_type == "char":
                    params.append(Value.char(str(p_val)[0] if p_val else "a"))

                elif p_type in ("int[]", "[I"):
                    # Expect list of ints
                    if not isinstance(p_val, list):
                        print("[WARN] Expected list for int[], got:", p_val)
                        p_val = []
                    params.append(Value.array(Int(), [int(x) for x in p_val]))

                elif p_type in ("char[]", "[C"):
                    if not isinstance(p_val, list):
                        print("[WARN] Expected list for char[], got:", p_val)
                        p_val = []
                    params.append(Value.array(Char(), [str(x)[0] for x in p_val]))

                else:
                    print("[WARN] Unknown LLM type in _llm_to_inputs:", p)

            cases.append(Input(tuple(params)))

        return cases

    def generate_llm_cases(
        self,
        count: int = GEN_BATCH_SIZE,
        previous_results: List[Dict[str, Any]] | None = None,
    ) -> Tuple[List[Input], Any]:
        """
        Ask the LLM for new test cases, guided by:
        - method source
        - bytecode
        - previous fuzzing results

        Returns:
            (cases, usage_metadata)
        """
        previous_results = previous_results or []

        # JSON schema for the LLM response
        scheme = LLMResponse.model_json_schema()

        # ------------------------------------------------------------------
        # Extract readable method source
        # ------------------------------------------------------------------
        classname: jvm.ClassName = self.target.methodid.classname
        print(f"[DEBUG] Extracting source for method: {classname}")

        src_path = self.suite.sourcefile(classname)
        src = src_path.read_text(encoding="utf-8")

        # Bytecode mnemonics for context
        bytecode_ops = list(self.suite.method_opcodes(self.target.methodid))
        bytecode_mnemonics = [op.mnemonic() for op in bytecode_ops]

        # Try to extract the specific method body from Java source
        method_name = self.target.methodid.extension.name
        pattern = rf"(?s)\b{re.escape(method_name)}\s*\([^)]*\)\s*\{{.*?\}}"
        m = re.search(pattern, src)
        if m:
            method_source = m.group(0)
        else:
            method_source = f"// METHOD_BODY_NOT_FOUND for {method_name}"

        # Condensed history of previous results
        history = self.signature.build_previous_state_summary(previous_results)
        history_snippet = json.dumps(history, indent=2)

        # ------------------------------------------------------------------
        # Build the LLM prompt
        # ------------------------------------------------------------------
        prompt = f"""
            You are a program-analysis and fuzzing expert.

            We are fuzzing the Java method:
            {self.target.methodid}

            Expected behaviour / oracle classification:
            {self.target.result}

            SOURCE CODE (method body or approximation):
            {method_source}

            BYTECODE MNEMONICS (sequence of operations):
            {bytecode_mnemonics}

            PREVIOUS FUZZING RESULTS (most recent first):
            {history_snippet}

            Your task:
            - Generate {count} NEW fuzz inputs for this method.
            - Do NOT repeat any previous `input` values shown in PREVIOUS FUZZING RESULTS.
            - Inputs MUST be type-correct for the method signature {self.signature.param_types}.
            - Try to cover new execution behaviours or corner cases that may change the classification.
            - Some parameters may be arrays (e.g., int[] / [I); represent them as JSON lists of values.
            - Return ONLY JSON that conforms exactly to the provided JSON schema.

            JSON schema you must follow:
            {json.dumps(scheme, indent=2)}
            """

        parsed, usage = self.call_for_llm(prompt=prompt, scheme=scheme)

        if parsed is None:
            print("[ERROR] LLM returned None (parsed is None). Falling back to seed generation.")
            fallback = self.generate_new_cases(count)
            return fallback, usage

        print("[DEBUG] LLM raw parsed response:", parsed)

        if not isinstance(parsed, dict) or "new_cases" not in parsed:
            print("[ERROR] Parsed LLM response missing 'new_cases'. Falling back.")
            fallback = self.generate_new_cases(count)
            return fallback, usage

        llm_cases = parsed["new_cases"]
        cases = self._llm_to_inputs(llm_cases)
        return cases, usage

    # --------------------------------------------------------
    # LLM Call Wrapper
    # --------------------------------------------------------

    def call_for_llm(self, prompt: str = "", scheme: dict | None = None):
        """
        Thin wrapper around google-genai client to:
        - send prompt
        - request JSON schema-constrained output
        - return (parsed_json, usage_metadata)
        """
        from google import genai
        from google.genai import types

        load_dotenv()
        api_key = os.getenv("API_KEY")

        if not api_key:
            print("[ERROR] No API_KEY found in environment. Falling back to empty result.")
            return None, None

        client = genai.Client(api_key=api_key)

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_json_schema=scheme,
                temperature=0.2,
            ),
            contents=prompt,
        )

        print("[DEBUG] LLM parsed content:", response.parsed)
        print("[DEBUG] LLM usage metadata:", response.usage_metadata)

        return response.parsed, response.usage_metadata
