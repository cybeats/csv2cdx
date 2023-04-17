from parse import Parser
from build import Builder


if __name__ == "__main__":
    parser = Parser()

    setup, data, config = parser.get_data()

    print(setup)
    print(config)
    print(data)
       
   



