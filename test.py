from boofuzz.utils.enhanced_symbolic_execution import generate_protocol_data, generate_binary_data


for i in range(10):
    print("generate_protocol_data")
    print(generate_protocol_data('redis', 'values', 10, use_ai=True))
    print(generate_binary_data('random', 20))
    