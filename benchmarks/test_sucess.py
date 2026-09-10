import random
import string
import csv
import os
from collections import defaultdict

def generate_random_string(length=32, charset=string.ascii_letters + string.digits, secure=False):
    """
    Generate a random string; when secure=True, the system random generator is used
    """
    if secure:
        return ''.join(random.SystemRandom().choices(charset, k=length))
    return ''.join(random.choices(charset, k=length))

def benchmark_ncRNA_success_rate(ncRNA_encrypt, ncRNA_decrypt, data_lengths, run_times):
    """
    For the ncRNA algorithm, count the encryption and decryption success rates at different data lengths
    """
    # Record the encryption/decryption successes and failures for each data length
    results = defaultdict(lambda: {"enc_success": 0, "enc_fail": 0,
                                   "dec_success": 0, "dec_fail": 0})
    
    for data_length in data_lengths:
        # Generate the test plaintext
        plaintext = generate_random_string(data_length)
        
        for _ in range(run_times):
            try:
                # Prepare the required parameters before encryption
                seed = generate_random_string(32, string.digits, secure=True).encode()
                seed_sequence = generate_random_string(32, charset='ACGU', secure=True)
                salt = generate_random_string(16, secure=True)
                
                # Call the encryption function, assumed to return a tuple whose first item is the encrypted data and whose remaining items are the extra parameters needed for decryption
                encrypted_data_tuple = ncRNA_encrypt(plaintext, seed, seed_sequence, salt)
                encrypted_data = encrypted_data_tuple[0]
                results[data_length]["enc_success"] += 1
            except Exception as e:
                # If an exception occurs during encryption, count it as an encryption failure and treat the decryption as failed too
                results[data_length]["enc_fail"] += 1
                results[data_length]["dec_fail"] += 1
                continue

            try:
                # Call the decryption function and check whether the decrypted plaintext matches the original plaintext
                decrypted_text = ncRNA_decrypt(encrypted_data, seed, seed_sequence, salt, *encrypted_data_tuple[1:])
                if decrypted_text == plaintext:
                    results[data_length]["dec_success"] += 1
                else:
                    results[data_length]["dec_fail"] += 1
            except Exception as e:
                results[data_length]["dec_fail"] += 1

    return results

def save_success_rate_csv(results, file_path):
    """
    Save the test results to a CSV file
    """
    # Create the directory if it does not exist
    directory = os.path.dirname(file_path)
    if not os.path.exists(directory):
        os.makedirs(directory)
        
    with open(file_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        # Write the header
        writer.writerow(["Data Length", "Total Runs",
                         "Encryption Success", "Encryption Failure",
                         "Decryption Success", "Decryption Failure",
                         "Encryption Success Rate (%)", "Decryption Success Rate (%)"])
        
        # Compute the success rates for each data length and write them to the CSV
        for data_length, counts in results.items():
            total_runs = counts["enc_success"] + counts["enc_fail"]
            enc_success_rate = (counts["enc_success"] / total_runs * 100) if total_runs > 0 else 0
            dec_success_rate = (counts["dec_success"] / total_runs * 100) if total_runs > 0 else 0
            
            writer.writerow([data_length, total_runs,
                             counts["enc_success"], counts["enc_fail"],
                             counts["dec_success"], counts["dec_fail"],
                             f"{enc_success_rate:.2f}", f"{dec_success_rate:.2f}"])
    
    print(f"Success rate CSV saved to {file_path}")

def find_next_file_number(directory):
    """
    Return the next available file number in the given directory
    """
    if not os.path.exists(directory):
        os.makedirs(directory)
    
    existing_files = os.listdir(directory)
    existing_numbers = []
    
    for file_name in existing_files:
        if file_name.endswith(".csv"):
            try:
                # Assume the file name format is ncRNA_success_<number>.csv
                num = int(file_name.split("_")[2].split(".")[0])
                existing_numbers.append(num)
            except ValueError:
                continue
    
    next_number = max(existing_numbers, default=0) + 1
    return next_number

def main():
    # Test parameters: different data lengths and the number of runs per length
    data_lengths = [50, 100, 1000, 100000, 1000000]
    run_times = 10

    # Import the encryption and decryption functions of the ncRNA algorithm (make sure this module path is correct)
    from algorithm.ncRNA3_5 import encrypt as ncRNA_encrypt, decrypt as ncRNA_decrypt

    # Run the success rate test
    results = benchmark_ncRNA_success_rate(ncRNA_encrypt, ncRNA_decrypt, data_lengths, run_times)

    # Specify the directory and file number for saving the results
    directory = "./results/csv/success_rate"
    next_number = find_next_file_number(directory)
    file_path = f"{directory}/ncRNA_success_{next_number}.csv"

    # Save the results to CSV
    save_success_rate_csv(results, file_path)

if __name__ == "__main__":
    main()