import fuzzer as fuzzer
class methodidextracter:
    "Extract the method id from the classes"

    def __init__(self) -> None:
        pass

    def extracrt_json(method_id):
        #extract the name of the json from the given file
        line=fuzzer.codefinder(method_id)
        json_name_list=line.split()
        json_name=json_name_list[2]
        return json_name