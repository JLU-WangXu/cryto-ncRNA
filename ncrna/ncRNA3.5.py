import hashlib  # hashlib for hashing
import random   # random for random number generation
import time     # time for timing
from collections import Counter  # Counter for counting occurrences
from Crypto.Cipher import AES  # AES cipher
from Crypto.Util.Padding import pad, unpad  # padding helpers
import base64   # base64 for encoding
import math     # math for numeric operations
import matplotlib.pyplot as plt  # plotting
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256  # hash module for PBKDF2
import numpy as np
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import multiprocessing
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes  # random byte generator
from Crypto.Cipher import ChaCha20  # ChaCha20 cipher

# Define the 64 codons
codons = np.array([a + b + c for a in 'ACGU' for b in 'ACGU' for c in 'ACGU'])

# Define the Base64 alphabet (excluding '=')
base64_chars = np.array(list('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'))

# can_pair, defined before it is used
def can_pair(base1, base2):
    """Check whether two RNA bases can pair.
    
    Allowed pairs: AU, UA, GC, CG, GU, UG
    """
    pairs = {
        ('A', 'U'), ('U', 'A'),
        ('G', 'C'), ('C', 'G'),
        ('G', 'U'), ('U', 'G')
    }
    return (base1, base2) in pairs

# 1. Generate codons on the fly with a generator instead of a precomputed array
def codon_generator():
    for a in 'ACGU':
        for b in 'ACGU':
            for c in 'ACGU':
                yield a + b + c

# 2. Build the codon substitution matrix
def generate_codon_substitution_matrix(seed):
    rng = random.Random(seed)
    codons_list = list(codon_generator())
    shuffled = codons_list.copy()
    rng.shuffle(shuffled)
    # Memory-saving dict comprehension
    return {k: v for k, v in zip(codons_list, shuffled)}

# process_chunk helper kept at module level
def process_chunk(chunk_and_matrix):
    """Helper that processes a chunk of codons
    
    Args:
        chunk_and_matrix: tuple (chunk, substitution_matrix)
    Returns:
        list: the substituted codons
    """
    chunk, substitution_matrix = chunk_and_matrix
    return [substitution_matrix[codon] for codon in chunk]

# substitute_codons
def substitute_codons(codon_sequence, substitution_matrix):
    """Substitute codons using a substitution matrix
    
    Args:
        codon_sequence: list of codons
        substitution_matrix: substitution matrix as a dict
    Returns:
        list: the substituted codon sequence
    """
    return [substitution_matrix[codon] for codon in codon_sequence]

# 3. linear_fold with reduced memory usage
def linear_fold(sequence):
    """Predict RNA secondary structure with the LinearFold algorithm
    
    Args:
        sequence: RNA sequence string
    Returns:
        structure: structure string in dot-bracket notation
    """
    n = len(sequence)
    # Use a plain list instead of a numpy array
    dp = [0] * n
    stack = []
    structure = ['.' for _ in range(n)]
    
    for i in range(n):
        while stack and can_pair(sequence[stack[-1]], sequence[i]):
            j = stack.pop()
            if i - j > 3:
                structure[j] = '('
                structure[i] = ')'
                dp[i] = dp[j] + 1
        
        if sequence[i] in 'ACGU':
            stack.append(i)
            
        if len(stack) > 30:
            stack = stack[-30:]
    
    return ''.join(structure)

# inverse_rna_secondary_structure
def inverse_rna_secondary_structure(codon_sequence, indices_order):
    """Undo the RNA secondary-structure reordering
    
    Args:
        codon_sequence: list of codons
        indices_order: the original reordering indices
    Returns:
        list: the restored codon sequence
    """
    # Join into a single sequence
    sequence = ''.join(codon_sequence)
    sequence_array = np.array(list(sequence))
    
    # Convert the indices to a numpy array
    indices_order_array = np.array(indices_order)
    
    # Validate that the lengths match
    if len(indices_order_array) != len(sequence_array):
        # On mismatch, trim both to the shorter length
        min_len = min(len(indices_order_array), len(sequence_array))
        sequence_array = sequence_array[:min_len]
        indices_order_array = indices_order_array[:min_len]
        print(f"Warning: sequence length adjusted to {min_len}")
    
    # Build the inverse index
    inverse_order = np.argsort(indices_order_array)
    
    # Apply the inverse permutation
    original_sequence_array = sequence_array[inverse_order]
    original_sequence = ''.join(original_sequence_array)
    
    # Ensure the result length is a multiple of 3
    if len(original_sequence) % 3 != 0:
        padding_length = 3 - (len(original_sequence) % 3)
        original_sequence = original_sequence + 'N' * padding_length
        print(f"Warning: added {padding_length} padding characters to make the length a multiple of 3")
    
    # Convert back to a codon sequence
    original_codon_sequence = [original_sequence[i:i+3] for i in range(0, len(original_sequence), 3)]
    
    return original_codon_sequence

# 4. apply_rna_secondary_structure
def apply_rna_secondary_structure(codon_sequence):
    """Apply the RNA secondary-structure reordering
    
    Args:
        codon_sequence: list of codons
    Returns:
        tuple: (reordered codon sequence, index order)
    """
    base_sequence = ''.join(codon_sequence)
    structure = linear_fold(base_sequence)
    
    # Use list comprehensions instead of numpy operations
    paired_indices = [i for i, c in enumerate(structure) if c in '()']
    unpaired_indices = [i for i, c in enumerate(structure) if c == '.']
    indices_order = paired_indices + unpaired_indices
    
    # Use list operations instead of numpy reordering
    new_sequence = ''.join(base_sequence[i] for i in indices_order)
    new_codon_sequence = [new_sequence[i:i+3] for i in range(0, len(new_sequence), 3)]
    
    return new_codon_sequence, indices_order

# 5. Derive a dynamic key from biological data
def generate_dynamic_key_from_biological_data(seed_sequence, salt, iterations=100000):
    valid_bases = set('ACGU')
    if not set(seed_sequence.upper()).issubset(valid_bases):
        raise ValueError("Seed sequence contains invalid bases.")
    dynamic_key = PBKDF2(seed_sequence, salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)
    return dynamic_key

# 6. AES encryption
def aes_encrypt(data_sequence, key):
    data_str = ''.join(data_sequence)
    data_bytes = data_str.encode()
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(pad(data_bytes, AES.block_size))
    return cipher.nonce + tag + ciphertext

# 7. Append a checksum
def add_checksum(encrypted_data):
    checksum = hashlib.sha256(encrypted_data).digest()
    return encrypted_data + checksum

# Stream cipher encryption
def cha_encrypt(data, key):
    """Encrypt data with ChaCha20
    
    Args:
        data: data to encrypt (bytes or str)
        key: encryption key
    Returns:
        bytes: nonce + encrypted data
    """
    # Ensure the input data is bytes
    if isinstance(data, str):
        data_bytes = data.encode('utf-8')
    else:
        data_bytes = data
        
    cipher = ChaCha20.new(key=key)
    ciphertext = cipher.nonce + cipher.encrypt(data_bytes)
    return ciphertext

# inverse_substitute_codons, defined before decrypt
def inverse_substitute_codons(codon_sequence, substitution_matrix):
    """Reverse-substitute codons, mapping substituted codons back to the originals"""
    inverse_matrix = {v: k for k, v in substitution_matrix.items()}
    original_codon_sequence = []
    
    for i, codon in enumerate(codon_sequence):
        if codon not in inverse_matrix:
            raise ValueError(f"No inverse substitution found for codon '{codon}'")
        original_codon_sequence.append(inverse_matrix[codon])
    
    return original_codon_sequence

# decode_codons_to_plaintext
def decode_codons_to_plaintext(codon_sequence):
    """Decode a codon sequence back into a plaintext string"""
    try:
        # Join the codon sequence into a string
        codon_str = ''.join(codon_sequence)
        
        # Ensure the codon length is a multiple of 3
        if len(codon_str) % 3 != 0:
            padding_length = 3 - (len(codon_str) % 3)
            codon_str = codon_str + 'N' * padding_length
        
        # Split into a list of codons
        codons_list = [codon_str[i:i+3] for i in range(0, len(codon_str), 3)]
        
        # Convert codons to indices
        codon_indices = []
        for codon in codons_list:
            try:
                idx = np.where(codons == codon)[0][0]
                codon_indices.append(idx)
            except IndexError:
                print(f"Warning: skipping invalid codon '{codon}'")
                continue
        
        # Convert to Base64 characters
        base64_str = ''.join(base64_chars[idx % 64] for idx in codon_indices)
        
        # Add Base64 padding
        padding_length = -len(base64_str) % 4
        base64_padded = base64_str + '=' * padding_length
        
        # Decode Base64
        try:
            plaintext_bytes = base64.b64decode(base64_padded)
            return plaintext_bytes.decode('utf-8')
        except Exception as e:
            print(f"Base64 decoding failed, falling back: {str(e)}")
            # Fall back to returning the string as is
            return base64_str
            
    except Exception as e:
        print(f"Decoding error: {str(e)}")
        raise

# decrypt
def decrypt(encrypted_data_with_checksum, seed, seed_sequence, salt, substitution_matrix, indices_order):
    encrypted_data = verify_and_remove_checksum(encrypted_data_with_checksum)
    dynamic_key = generate_dynamic_key_from_biological_data(seed_sequence, salt)
    decrypted_sequence = cha_decrypt(encrypted_data, dynamic_key)
    unfolded_sequence = inverse_rna_secondary_structure(decrypted_sequence, indices_order)
    original_codon_sequence = inverse_substitute_codons(unfolded_sequence, substitution_matrix)
    plaintext = decode_codons_to_plaintext(original_codon_sequence)
    return plaintext

# Checksum verification
def verify_and_remove_checksum(encrypted_data_with_checksum):
    encrypted_data = encrypted_data_with_checksum[:-32]
    checksum = encrypted_data_with_checksum[-32:]
    computed_checksum = hashlib.sha256(encrypted_data).digest()
    if checksum != computed_checksum:
        raise ValueError("Checksum does not match. Data may be corrupted.")
    return encrypted_data

# Stream cipher decryption (replaces AES decryption)
def cha_decrypt(encrypted_data, key):
    """Decrypt data with ChaCha20
    
    Args:
        encrypted_data: encrypted data (nonce included)
        key: decryption key
    Returns:
        list: the decrypted codon sequence
    """
    try:
        nonce = encrypted_data[:8]  # ChaCha20 uses an 8-byte nonce
        ciphertext = encrypted_data[8:]
        cipher = ChaCha20.new(key=key, nonce=nonce)
        decrypted_data = cipher.decrypt(ciphertext)
        
        # Try several encodings
        for encoding in ['utf-8', 'latin1', 'ascii']:
            try:
                data_str = decrypted_data.decode(encoding)
                # Check that the decoded data looks like a codon sequence
                if len(data_str) % 3 == 0 and all(c in 'ACGU' for c in data_str):
                    codon_sequence = [data_str[i:i+3] for i in range(0, len(data_str), 3)]
                    return codon_sequence
            except UnicodeDecodeError:
                continue
        
        # If every encoding fails, fall back to per-character decoding
        data_str = ''.join(chr(b) for b in decrypted_data)
        codon_sequence = [data_str[i:i+3] for i in range(0, len(data_str), 3)]
        return codon_sequence
        
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        raise

# Compute entropy
def calculate_entropy(data):
    byte_data = data
    if isinstance(data, str):
        byte_data = data.encode()
    data_length = len(byte_data)
    if data_length == 0:
        return 0.0
    frequencies = Counter(byte_data)
    freqs = np.array(list(frequencies.values()), dtype=float)
    probabilities = freqs / data_length
    entropy = -np.sum(probabilities * np.log2(probabilities))
    return entropy

# Plot the entropy histogram
def plot_entropy_histogram(data):
    byte_data = data
    if isinstance(data, str):
        byte_data = data.encode()
    frequencies = Counter(byte_data)
    bytes_list = np.array(list(frequencies.keys()))
    counts = np.array(list(frequencies.values()))
    plt.bar(bytes_list, counts)
    plt.xlabel('Byte Value')
    plt.ylabel('Frequency')
    plt.title('Byte Frequency Distribution of Encrypted Data')
    plt.show()

# Performance test
def test_performance():
    plaintext_lengths = [50, 100, 200, 400, 800, 1600]
    encryption_times = []
    decryption_times = []
    seed = "123456789"
    seed_sequence = "ACGUACGUACGUACGUACGUACGUACGUACGU"
    salt = b'salt_123'

    def process_length(length):
        plaintext = 'A' * length
        start_time = time.time()
        encrypted_data_with_checksum, substitution_matrix, indices_order = encrypt(plaintext, seed, seed_sequence, salt)
        encryption_time = time.time() - start_time
        start_time = time.time()
        decrypted_plaintext = decrypt(encrypted_data_with_checksum, seed, seed_sequence, salt, substitution_matrix, indices_order)
        decryption_time = time.time() - start_time
        return (encryption_time, decryption_time)

    with ThreadPoolExecutor() as executor:
        results = executor.map(process_length, plaintext_lengths)
        for et, dt in results:
            encryption_times.append(et)
            decryption_times.append(dt)

    plt.plot(plaintext_lengths, encryption_times, label='Encryption Time')
    plt.plot(plaintext_lengths, decryption_times, label='Decryption Time')
    plt.xlabel('Plaintext Length (characters)')
    plt.ylabel('Time (seconds)')
    plt.title('Encryption and Decryption Time vs. Plaintext Length')
    plt.legend()
    plt.show()

def test_comparison():
    """Compare ncRNA, AES and RSA performance"""
    plaintext_lengths = [50, 100, 200, 400, 800, 1600]
    ncrna_times = []
    aes_times = []
    rsa_times = []
    
    # Initialize keys
    seed = "123456789"
    seed_sequence = "ACGUACGUACGUACGUACGUACGUACGUACGU"
    salt = b'salt_123'
    aes_key = get_random_bytes(32)
    rsa_key = RSA.generate(2048)
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    
    def test_ncrna(plaintext):
        start_time = time.time()
        encrypted_data, _, _ = encrypt(plaintext, seed, seed_sequence, salt)
        return time.time() - start_time
    
    def test_aes(plaintext):
        start_time = time.time()
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(pad(plaintext.encode(), AES.block_size))
        return time.time() - start_time
    
    def test_rsa(plaintext):
        start_time = time.time()
        # RSA can only encrypt a limited length at a time, so chunk the input
        block_size = 190  # Maximum encryption block size for RSA-2048
        blocks = [plaintext[i:i+block_size].encode() for i in range(0, len(plaintext), block_size)]
        for block in blocks:
            rsa_cipher.encrypt(block)
        return time.time() - start_time

    for length in plaintext_lengths:
        test_text = 'A' * length
        ncrna_times.append(test_ncrna(test_text))
        aes_times.append(test_aes(test_text))
        rsa_times.append(test_rsa(test_text))

    # Plot the performance comparison
    plt.figure(figsize=(10, 6))
    plt.plot(plaintext_lengths, ncrna_times, 'o-', label='ncRNA')
    plt.plot(plaintext_lengths, aes_times, 's-', label='AES')
    plt.plot(plaintext_lengths, rsa_times, '^-', label='RSA')
    plt.xlabel('Plaintext Length (characters)')
    plt.ylabel('Encryption Time (seconds)')
    plt.title('Encryption Algorithm Performance Comparison')
    plt.legend()
    plt.grid(True)
    plt.show()

    # Print detailed results
    print("\nPerformance comparison:")
    print("Plaintext length\tncRNA(s)\tAES(s)\t\tRSA(s)")
    print("-" * 50)
    for i, length in enumerate(plaintext_lengths):
        print(f"{length}\t\t{ncrna_times[i]:.6f}\t{aes_times[i]:.6f}\t{rsa_times[i]:.6f}")

# Build and pad a data chunk
def prepare_data_chunk(chunk):
    """Prepare a data chunk for encryption
    
    Args:
        chunk: list of codons
    Returns:
        bytes: the prepared data chunk
    """
    # Join the codon list into a string
    chunk_str = ''.join(chunk)
    # Encode the string to bytes and pad it
    return pad(chunk_str.encode(), AES.block_size)

# encode_plaintext_to_codons, defined before encrypt
def encode_plaintext_to_codons(plaintext):
    """Encode a plaintext string into a codon sequence
    
    Args:
        plaintext: plaintext string to encode
    Returns:
        list: the codon sequence
    """
    # Convert the plaintext to base64
    plaintext_bytes = plaintext.encode('utf-8')
    base64_bytes = base64.b64encode(plaintext_bytes)
    base64_str = base64_bytes.decode('ascii').rstrip('=')
    
    # Map base64 characters to indices
    char_to_index = {char: idx for idx, char in enumerate(base64_chars)}
    
    # Convert base64 characters to codons
    codon_sequence = []
    for char in base64_str:
        try:
            idx = char_to_index[char]
            codon = codons[idx]
            codon_sequence.append(codon)
        except (KeyError, IndexError):
            continue
    
    return codon_sequence

# encrypt
def encrypt(plaintext, seed, seed_sequence, salt):
    try:
        # 1. Encode the plaintext to codons
        codon_sequence = encode_plaintext_to_codons(plaintext)
        
        # 2. Build the substitution matrix
        substitution_matrix = generate_codon_substitution_matrix(seed)
        
        # 3. Substitute codons
        substituted_sequence = substitute_codons(codon_sequence, substitution_matrix)
        
        # 4. Apply the RNA secondary structure
        structured_sequence, indices_order = apply_rna_secondary_structure(substituted_sequence)
        
        # 5. Derive the dynamic key
        dynamic_key = generate_dynamic_key_from_biological_data(seed_sequence, salt)
        
        # 6. Prepare the data to encrypt
        data_to_encrypt = ''.join(structured_sequence)
        
        # 7. Encrypt with ChaCha20
        encrypted_data = cha_encrypt(data_to_encrypt, dynamic_key)
        
        # 8. Append the checksum
        encrypted_data_with_checksum = add_checksum(encrypted_data)
        
        return encrypted_data_with_checksum, substitution_matrix, indices_order
        
    except Exception as e:
        print(f"Encryption error: {str(e)}")
        raise

# Test code
if __name__ == "__main__":
    DEBUG = False  # Debug output only when True
    
    # Basic encryption test
    num_threads = multiprocessing.cpu_count()
    plaintext = "Hello, World! This is a test of the encryption algorithm based on ncRNA."
    seed = "123456789"
    seed_sequence = "ACGUACGUACGUACGUACGUACGUACGUACGU"
    salt = b'salt_123'
    
    if DEBUG:
        start_time = time.time()
        encrypted_data_with_checksum, substitution_matrix, indices_order = encrypt(
            plaintext, seed, seed_sequence, salt
        )
        encryption_time = time.time() - start_time
        print(f"Encryption finished in {encryption_time:.6f} s")
        encrypted_data = encrypted_data_with_checksum[:-32]
        entropy = calculate_entropy(encrypted_data)
        print(f"Entropy of the encrypted data: {entropy:.4f} bits/byte")
        plot_entropy_histogram(encrypted_data)

    # Run the performance tests
    print("\n=== Performance tests ===")
    print("1. ncRNA encryption/decryption performance")
    test_performance()
    
    print("\n2. ncRNA vs AES vs RSA comparison")
    test_comparison()

def chunked_encryption(plaintext, chunk_size=400):
    chunks = [plaintext[i:i+chunk_size] for i in range(0, len(plaintext), chunk_size)]
    encrypted_chunks = []
    for chunk in chunks:
        # Process each smaller chunk
        encrypted_chunk = encrypt_chunk(chunk)
        encrypted_chunks.append(encrypted_chunk)
    return combine_chunks(encrypted_chunks)

def optimized_nussinov(sequence):
    # Sparse dynamic programming
    # Store only the positions that can pair
    pairs = {}
    for i in range(len(sequence)):
        for j in range(i + 4, len(sequence)):  # Minimum loop size of 4
            if can_pair(sequence[i], sequence[j]):
                pairs[(i,j)] = True
    # Compute only at positions that can pair

# Process large inputs in chunks
def process_large_file(plaintext, chunk_size=1024):
    """Process a large input in chunks to reduce memory usage"""
    chunks = (plaintext[i:i+chunk_size] for i in range(0, len(plaintext), chunk_size))
    results = []
    
    for chunk in chunks:
        encrypted_chunk = encrypt(chunk, seed, seed_sequence, salt)
        results.append(encrypted_chunk)
        
    return combine_results(results)