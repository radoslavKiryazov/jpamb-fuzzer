import random
import copy
import string
from typing import List
from google import genai
from jpamb import jvm
from jpamb.jvm.base import (
    Value, Int, Boolean, Char, Array, Type,
)
from jpamb.model import Input
from jpamb.jfuzzer.report_preprocess.parser import Report_Item


class SignatureHandler:
    """
    JPAMB-native signature handler.
    No string parsing.
    """

    def __init__(self, abs_methodid: jvm.AbsMethodID):
        # abs_methodid.extension is a MethodID object!!!!!!!!
        method = abs_methodid.extension

        self.param_types = list(method.params._elements)
        self.return_type = method.return_type

        print("[DEBUG] JPAMB param types:", self.param_types)

    def values_for_type(self, t: Type):
        """Return example Python values for JPAMB types"""

        # int
        if isinstance(t, Int):
            return [0, 1, -1, 42, 1337]

        # boolean
        if isinstance(t, Boolean):
            return [True, False]

        # char
        if isinstance(t, Char):
            return ["a", "b", "Z"]

        # arrays
        if isinstance(t, Array):
            elem = t.contains

            if isinstance(elem, Int):
                return [[], [1], [1, 2, 3], [-1, 0, 1]]

            if isinstance(elem, Char):
                return [["a"], ["a","b","c"]]

            return [[]]

        # fallback
        return [None]

    def generate_seeds(self):
        """Return all valid combinations"""
        from itertools import product

        if not self.param_types:
            return [()]

        value_lists = [self.values_for_type(t) for t in self.param_types]
        return list(product(*value_lists))


#  Case Generator now with signatures
class CaseGenerator:
    GEN_BATCH_SIZE = 20

    def __init__(self, report_item: Report_Item) -> None:
        self.target = report_item
        print(f"[DEBUG] Initializing CaseGenerator with Report_Item: {report_item}")
        self.signature = SignatureHandler(report_item.methodid)


    def _mutate_int(self, value):
        return value + random.randint(-5, 5)


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
    
    def generate_llm_cases(self, count=GEN_BATCH_SIZE):
        # client reads api key from the enviroment
        client = genai.Client(api_key="YOUR_API_KEY")

        # reads prompt from prompt.txt
        with open('prompt.txt') as f:
            prompt = f.readlines()

        # saves the response as a variable
        response = client.models.generate_content(
            model="gemini-2.5-flash", contents=prompt
        )

        # prints the response
        print(response.text)



# test for the hood
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

    for case in case_gen.generate_new_cases(5):
        print(case.encode())

    for case in case_gen.generate_mutated_cases(5):
        print(case.encode())
