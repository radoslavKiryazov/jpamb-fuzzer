from jfuzzer.util.ParserAssistant import ast_parser
from jfuzzer.util.oracle import oracle


class fuzzer:
    """
    Fuzzer core logic to run fuzzing on given targets with test cases.
    """


    def __init__(self) -> None:
        pass


    @staticmethod
    def code_finder(method_id):
        return None  # Placeholder for actual code finding logic 


    @staticmethod
    def construct_fuzz_cmd():
        return None  # Placeholder for actual command construction logic


    # Oracle: determines if a crash or unexpected behavior occurred
    def crash_oracle(self, execution_output, target):
        # Placeholder for actual oracle logic
        return False
    

    def some_other_oracle(self, execution_output, target):
        pass


    def target_build(self):
        return None  # Placeholder for actual target building logic
    

    def target_wrap(self, slice):
        return None  # Placeholder for actual target wrapping logic
    

    def target_run(self, fuzzing_wrapper):
        return (the running instance)  # Placeholder for actual target running logic


    def run_fuzzer(self, target, test_cases):
        # 1. build the target (optional, for efficiency)
        
        

        # 2. structural information about the soruce code
        target_ast = ast_parser.parse(target)
        SUT = code_finder(target.method_id, target_ast)

        
        # 3. generate the minimal source code (slice) needed for the target to be working
        slice = self.target_build()


        # 4. compile the slice --> get the fuzzing wraper, i.e. the actual target to run
        fuzzing_wrapper = self.target_wrap(slice)


        # 5. pass test cases to the fuzzing wrapper, (monitor the execution), oracle checking, classify results
        live_target = self.target_run(fuzzing_wrapper)
        fz_results = None
        while(fz_results = oracle.run(live_target)):
            live_target.run_next(test_cases)


        # 6. return esults
        #   result["status"] can be:
        #   C - There is at least one crash/buffer overflow at warning location
        #   PFP - There is no crash/buffer overflow at the warning location, but the line is executed - Possible False Positive
        #   NR - The warning line is not executed - Not Reachable
        #   NC - The slice is not compiled - Not Compiled
        #   TO - Timeout during fuzzing

        results = {
            "status": fz_results,  # Example status
            "issue": target.method_id + ":" + target.error
        }
        return results
    