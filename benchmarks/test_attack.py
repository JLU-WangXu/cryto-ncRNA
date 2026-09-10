import random
import string
import numpy as np
from qiskit import AerSimulator
from qiskit.aqua.algorithms import Grover
from qiskit.aqua.components.oracles import LogicalExpressionOracle
from dataclasses import dataclass
import matplotlib.pyplot as plt
import pandas as pd

# Data lengths and encryption parameters
@dataclass
class EncryptionArgs:
    plaintext: str
    data_length: int
    params: tuple

def generate_random_string(length=32, charset=string.ascii_letters + string.digits):
    """Generate a random string, used to simulate keys and ciphertext"""
    return ''.join(random.choices(charset, k=length))

def quantum_attack_simulation(encrypt_function, decrypt_function, plaintext, seed, seed_sequence, salt, max_attempts=1000):
    """
    Simulate a quantum-computing brute-force attack on the key and the ciphertext
    :param encrypt_function: encryption function
    :param decrypt_function: decryption function
    :param plaintext: plaintext
    :param seed: random seed
    :param seed_sequence: random sequence
    :param salt: salt value
    :param max_attempts: maximum number of attempts (simulating the parallelism of quantum computing)
    :return: whether the ciphertext was broken successfully
    """
    # Use the provided encryption function
    encrypted_data_tuple = encrypt_function(plaintext, seed, seed_sequence, salt)  # Encrypt
    encrypted_data = encrypted_data_tuple[0]  # Get the encrypted data
    encryption_params = encrypted_data_tuple[1:]  # Get the other parameters needed for decryption (e.g. the key)

    # Use Qiskit's Grover algorithm for the quantum brute-force attack
    oracle_expression = ''.join(['1' if char == '1' else '0' for char in encrypted_data])
    oracle = LogicalExpressionOracle(oracle_expression)

    grover = Grover(oracle)
    backend = AerSimulator()  # Use the latest AerSimulator
    result = grover.run(backend)
    
    # Get the quantum computing result to break the key
    measured_key = result['result'][0]

    # Decrypt with the decryption function and verify whether it succeeded
    decrypted_data = decrypt_function(encrypted_data, seed, seed_sequence, salt, *encryption_params)
    return decrypted_data == plaintext, measured_key

def benchmark_quantum_attack_for_ncRNA(encrypt_function, decrypt_function, data_lengths, key_lengths, runs=10):
    attack_results = {}
    for data_length in data_lengths:
        attack_results[data_length] = {}
        for key_length in key_lengths:
            keyspace = [generate_random_string(key_length) for _ in range(100)]  # Simulated key space
            run_results = []
            for _ in range(runs):
                plaintext = generate_random_string(data_length)
                seed = random.randint(0, 2**32 - 1)
                seed_sequence = generate_random_string(key_length)
                salt = generate_random_string(key_length)
                success, key = quantum_attack_simulation(encrypt_function, decrypt_function, plaintext, seed, seed_sequence, salt)
                run_results.append(success)
            success_rate = np.mean(run_results)
            attack_results[data_length][key_length] = success_rate
    return attack_results

def plot_attack_results(attack_results):
    """Plot the quantum computing attack success rate"""
    df = pd.DataFrame.from_dict({(i, j): attack_results[i][j] for i in attack_results for j in attack_results[i]}, 
                                orient='index', columns=['Success Rate'])
    df.index = pd.MultiIndex.from_tuples(df.index, names=['Data Length', 'Key Length'])
    df = df.reset_index()

    # Draw the figure
    plt.figure(figsize=(12, 8))
    for key_length in df['Key Length'].unique():
        subset = df[df['Key Length'] == key_length]
        plt.plot(subset['Data Length'], subset['Success Rate'], label=f'Key Length {key_length}')
    
    plt.xlabel('Data Length (Bytes)')
    plt.ylabel('Attack Success Rate')
    plt.title('Quantum Computing Attack Simulation on ncRNA Algorithm')
    plt.legend()
    plt.grid(True)
    plt.show()

def main():
    data_lengths = [70, 100, 500, 1000, 5000, 10000]
    key_lengths = [16, 32, 64]  # Assumed key lengths
    runs = 10

    # Import the encryption and decryption functions from the ncRNA encryption algorithm
    from algorithm.ncRNA3_5 import encrypt as ncRNA_encrypt, decrypt as ncRNA_decrypt

    # Run the quantum computing attack resistance test
    print(f"Testing ncRNA algorithm for quantum computing attack simulation")
    attack_results = benchmark_quantum_attack_for_ncRNA(ncRNA_encrypt, ncRNA_decrypt, data_lengths, key_lengths, runs)
    plot_attack_results(attack_results)

if __name__ == "__main__":
    main()
