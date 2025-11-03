import json

class CaseLoader:
    def __init__(self, file_path):
        self.file_path = file_path
        self.data = None

    def load(self):
        with open(self.file_path, 'r') as file:
            self.data = json.load(file)
        return self.data