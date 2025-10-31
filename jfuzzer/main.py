import time
import timeout_decorator

from fuzzcore import fuzzer
from fuzzgen import casegen
from report_preprocess import parser
from result_analysis import analyzer


if __name__ == "__main__":
    # 1. load the config, initialization
    config = {}


    # 2. load the report, pre-process, etc.
    report = parser.parse(config)  # Load the report
    

    # 3. run the fuzzer main loop, and classify results
    # fuzzing_result["status"] can be:
    #   C - There is at least one crash/buffer overflow at warning location
    #   PFP - There is no crash/buffer overflow at the warning location, but the line is executed - Possible False Positive
    #   NR - The warning line is not executed - Not Reachable
    #   NC - The slice is not compiled - Not Compiled
    #   TO - Timeout during fuzzing

    fuzzing_result = {}
    for item in report:
        start = time.time()

        cases = casegen.generate_cases(item)
        casegen_time = time.time()

        try: 
            fuzzing_result = fuzzer.run_fuzzer(item, cases)
        except timeout_decorator.TimeoutError as e:
            print(f"Fuzzing timed out for issue {item.method_id}: {e}")
            fuzzing_result = {"status": "TO"}
            continue

        end = time.time()
        print(f"Fuzzing for issue {item.method_id} completed in {end - start} seconds.")

        fuzzing_result["time_casegen"] = casegen_time - start
        fuzzing_result["time_fuzz"] = end - casegen_time
        fuzzing_result["time_total"] = end - start

        # with open(log_location, "a") as fp:
        #     fp.write(json.dumps(fuzz_data)+"\n")

    pruned_results = analyzer.analyze_results(fuzzing_result)
    