from parse import Parser
from build import Builder2


if __name__ == "__main__":
    parser = Parser()

    args, data, config = parser.get_data()

    # print(type(data))
    # print(len(data.columns))

    # print("\nsetup data")
    # for k, v in args.items():
    #     print(k, "=", v)

    # print("\nconfig data")
    # for k, v in config.items():
    #     print(k, "=", v)

    # print("\ncsv data")
    # print(data)

    builder = Builder2(args, data, config)

    # comp_list = builder.assemble_components(data, config)
    #print(builder.ouput_file)
    builder.build_sbom()





