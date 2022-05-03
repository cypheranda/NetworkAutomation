def get_device_data(inventory):
    elements = []

    fin = open(inventory, "r")
    for line in fin:
        if line[0] == '[':
            if line[len(line)-2] == ']':
                if ':' not in line:
                    elements.append(line[1:(len(line)-2)])

    fin.close()
    return elements

# elements = get_device_data("inventory")
# print("STARTIN")
# for element in elements:
#     print(element)
