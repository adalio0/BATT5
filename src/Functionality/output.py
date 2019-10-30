class Output:

    # getter methods
    def __init__(self):
        x = ""
        self._name = x
        self._description = x
        self._file = x
        

    def get_name(self):
        return self._name

    def get_description(self):
        return self._description
        
    def get_file(self):
        return self._file
    # setter method
    def set_name(self, x):
        self._name = x

    def set_description(self, x):
        self._description = x

    def set_file(self, x):
        self._file = x
    