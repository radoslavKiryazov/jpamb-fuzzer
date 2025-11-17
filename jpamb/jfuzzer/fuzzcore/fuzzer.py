# from caseloader import caseloader


# class fuzzer:
#     """
#     Fuzzer core logic to run fuzzing on given targets with test cases.
#     """
#     def __init__(self) -> None:
#         pass


#     # @staticmethod
#     # #collect offsets for coverage guided 
#     # def code_finder(method_id):
#     #     extracter = json_name_extracter()
#     #     name = extracter.extract_json(method_id) 
        
#     #     caseloader = caseloader(name)
#     #     caseloader.load()

             
#     #     return None  # Placeholder for actual code finding logic 


#     @staticmethod
#     def construct_fuzz_cmd():
#         return None  # Placeholder for actual command construction logic


#     # Oracle: determines if a crash or unexpected behavior occurred
#     def crash_oracle(self, execution_output, target):
#         # Placeholder for actual oracle logic
#         return False
    

#     def some_other_Foracle(self, execution_output, target):
#         pass


#     @staticmethod
#     def run_fuzzer(target, test_cases):
#         # target: method_id, trigger input, error type
#         # example: jpamb.cases.Simple.assertInteger:(0) -> assertion error

#         # SUT = code_finder(target.method_id)
#         fz_results = "NC"  # Default status
        
#         # run the internal fuzzer pass test cases and method.id
        
        

#         results = {
#             "status": fz_results,  # Example status
#             "issue": target.method_id + ":" + target.error
#         }
#         return results


#     #   result["status"] can be:
#     #   C - There is at least one crash/buffer overflow at warning location
#     #   PFP - There is no crash/buffer overflow at the warning location, but the line is executed - Possible False Positive
#     #   NR - The warning line is not executed - Not Reachable
#     #   NC - The slice is not compiled - Not Compiled
#     #   TO - Timeout during fuzzing
 