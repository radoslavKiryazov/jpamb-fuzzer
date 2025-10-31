import random
import copy
import string


#pip install libfuzzer (for next iteration)

class CaseGenerator:
    """
    Generates fuzzing cases for given method identifiers.
    """
    def __init__(self, parsed_results) -> None:
        self.parsed_results = parsed_results
        
    def generate_cases(self, count = 10):
        """
        Generate fuzzing cases for the given method identifier.
        """
        cases = []
        for i in range(count):
            case = f"case_{i}" # Placeholder for actual case generation logic;
            cases.append(case)
        return cases

    
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
