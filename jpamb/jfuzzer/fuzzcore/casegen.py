import random
import copy
import string
from jpamb.jvm.base import Value, Int, Char, Boolean, Array
from jpamb.jfuzzer.report_preprocess.parser import Report_Item
from jpamb.model import Input
from jpamb import jvm
from typing import List
from jpamb.jvm.base import Type


#pip install libfuzzer (for next iteration)

class CaseGenerator:
    """
    Generates fuzzing cases for given method identifiers.
    """
    def __init__(self, Report_Item) -> None:
        # target is a base as in suite.case
        self.target = Report_Item

    GEN_BATCH_SIZE = 20
    GEN_STRATEGY = {
        "default": "Combination of new and mutated inputs.",
        "new": "Generate entirely new inputs based on method signature.",
        "mutate": "Mutate existing valid inputs to create new test cases.", 
        "llm": "Use large language models to generate sophisticated inputs."
    }
    

    def _mutate(self, base_input):
        """
        Apply controlled mutations depending on the data type.
        """
        data = copy.deepcopy(base_input)
        
        if(isinstance(data, int)):
            self._mutate_int(data)
        elif(isinstance(data, str)):
            self._mutate_str(data)
        elif(isinstance(data, list)):
            self._mutate_list(data)
        elif(isinstance(data, dict)):
            self._mutate_dict(data)
        elif(isinstance(data, float)):
            self._mutate_float(data)
        else:
         return data;
   

    def _mutate_int(self, value):
        mutations = [
            lambda x: x + random.randint(-10, 10),
            lambda x: x * 2,
            lambda x: random.randint(-99999, 99999)
        ]
        return random.choice(mutations)(value)

    
    def _mutate_str(self, value):
        mutations = [
            lambda s: s + random.choice(string.ascii_letters),
            lambda s: s.upper(),
            lambda s: s + ''.join(random.choices(string.punctuation, k=2)),
        ]
        return random.choice(mutations)(value)

    
    def _mutate_list(self, value):
        return value + 1;

    
    def _mutate_float(self, value):
        mutations = [
            lambda x: x + random.uniform(-1.0, 1.0),
            lambda x: x * random.uniform(0.5, 2.0),
        ]
        return random.choice(mutations)(value)

    
    def _mutate_dict(self, d):
        d = copy.deepcopy(d)
        mutations = [
            lambda d: d.update({f"new_{random.randint(0, 100)}": random.randint(0, 100)}) or d,
        ]
        return random.choice(mutations)(d)
    
    
    def generate_new_cases(self, count = GEN_BATCH_SIZE) -> List[Input]:
        """
        Generate new fuzzing cases for the given method identifier.
        """
        cases = []
        return [
            Input((Value.int(0),)),
            Input((Value.int(0),)),
        ]
    
    
    def generate_mutated_cases(self, count = GEN_BATCH_SIZE):
        """
        Generate mutated fuzzing cases based on a base case.
        """

        # base case is self.target

        mutated_cases = []
        for i in range(count):
            mutated_case = self._mutate(5)
            mutated_cases.append(mutated_case)
        return mutated_cases


    def update_strategy(self, fuzzing_result=None, strategy_params=GEN_STRATEGY["default"]):
        """
        Update the case generation strategy based on previous fuzzing results.
        """
        # Placeholder for actual strategy update logic
        pass
