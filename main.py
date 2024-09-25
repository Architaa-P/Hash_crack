#!/usr/bin/env python3
import hashlib
import multiprocessing
import string
import subprocess
import time
import pyfiglet
import json  # Import json for handling the rainbow table

class Cracker(object):
    CHARSETS = {
        'lower': string.ascii_lowercase,
        'upper': string.ascii_uppercase,
        'digits': string.digits,
        'lower_digits': string.ascii_lowercase + string.digits,
        'upper_digits': string.ascii_uppercase + string.digits,
        'mixed': string.ascii_lowercase + string.ascii_uppercase,
        'mixed_digits': string.ascii_lowercase + string.ascii_uppercase + string.digits,
        'full': string.ascii_letters + string.digits + string.punctuation
    }

    @staticmethod
    def print_banner():
        banner = pyfiglet.figlet_format("Crack THE Hash", font="slant", justify="center")
        print("\033[1;31m" + banner + "\033[0m")  # Red and bold

    def __init__(self, hash_type, hash_val, charset):
        self.hash_type = hash_type
        self.hash_val = hash_val
        self.charset = charset
        self.found = multiprocessing.Event()
        self.rainbow_table = {}

    @staticmethod
    def _detect_hash_type(user_hash):
        """Detect hash type based on length."""
        if len(user_hash) == 32:
            return 'md5'
        elif len(user_hash) == 40:
            return 'sha1'
        elif len(user_hash) == 64:
            return 'sha256'
        elif len(user_hash) == 128:
            return 'sha512'
        return None

    def load_rainbow_table(self, filename):
        """Load the rainbow table from a JSON file."""
        with open(filename, 'r') as f:
            self.rainbow_table = json.load(f)

    def _rainbow_table_attack(self, done_queue):
        """Check if the hash exists in the rainbow table."""
        if self.hash_val in self.rainbow_table:
            done_queue.put(f"FOUND (Rainbow Table): Password is '{self.rainbow_table[self.hash_val]}'")
            self.found.set()
        else:
            done_queue.put("NOT FOUND")

    def _search_space(self, length):
        """Generate all possible combinations for the given charset and length."""
        queue = ['']
        while queue:
            candidate = queue.pop(0)
            if len(candidate) == length:
                yield candidate
            else:
                for char in self.charset:
                    queue.append(candidate + char)

    def _hash_function(self, data):
        """Create a hash based on the provided hash type."""
        if self.hash_type == 'md5':
            return hashlib.md5(data.encode('utf-8')).hexdigest()
        elif self.hash_type == 'sha1':
            return hashlib.sha1(data.encode('utf-8')).hexdigest()
        elif self.hash_type == 'sha256':
            return hashlib.sha256(data.encode('utf-8')).hexdigest()
        elif self.hash_type == 'sha512':
            return hashlib.sha512(data.encode('utf-8')).hexdigest()

    def _attempt_crack(self, length, done_queue):
        """Attempt to crack the password for a specific length."""
        for candidate in self._search_space(length):
            if self.found.is_set():
                return  # Stop if another process has already found the password
            candidate_hash = self._hash_function(candidate)

            if candidate_hash == self.hash_val:
                done_queue.put(f"FOUND: Password is '{candidate}'")
                self.found.set()
                return
        done_queue.put("NOT FOUND")

    def _dictionary_attack(self, done_queue):
        
        """Perform a dictionary attack to crack the password."""
        wordlists = ['/wordlist_path']
        
        for wordlist in wordlists:
            try:
                with open(wordlist, 'r', encoding='utf-8', errors='replace') as f:
                    for word in f:
                        word = word.strip().lower()
                        candidate_hash = self._hash_function(word)
                        if candidate_hash == self.hash_val:
                            done_queue.put(f"FOUND: Password is '{word}'")
                            self.found.set()
                            return
            except FileNotFoundError:
                print(f"Wordlist not found: {wordlist}")
        done_queue.put("NOT FOUND")

    def _run_john_the_ripper(self):
        """Run John the Ripper on the hash."""
        with open('hashes.txt', 'w') as f:
            f.write(self.hash_val + '\n')  # Save the hash to a file for John

        print("Starting John the Ripper...")

        # Adjust John the Ripper format based on hash type
        john_format = {
            'md5': 'raw-md5',
            'sha1': 'raw-sha1',
            'sha256': 'raw-sha256',
            'sha512': 'raw-sha512'
        }.get(self.hash_type, 'raw-md5')  # Default to md5 if hash type is not matched

        john_command = [r"PathToJohn", "--format=" + john_format, "hashes.txt"]
        john_process = subprocess.Popen(john_command)
        john_process.wait()  # Wait for John to finish

        # Check if John found the password
        john_output = subprocess.check_output([r"pathToJohn", "--show", "hashes.txt"]).decode()
        if self.hash_val in john_output:
            print("John the Ripper found the password!")
            print(john_output.strip())
            return True
        return False

    def start_cracking(self, workers=4, max_length=30, timeout=120):
        """Start the cracking process using rainbow table, dictionary, John the Ripper, and brute-force attacks."""
        start_time = time.time()

        processes = []
        done_queue = multiprocessing.Queue()

        # 1. Perform a dictionary attack first
        #print("Starting dictionary attack...")
        p = multiprocessing.Process(target=self._dictionary_attack, args=(done_queue,))
        processes.append(p)
        p.start()

        for p in processes:
            p.join()

        while not done_queue.empty():
            result = done_queue.get()
            if "FOUND" in result:
                print(result)
                return  # Exit if the password is found in the dictionary

        2. If the dictionary attack fails, perform a rainbow table attack
        print("Starting rainbow table attack...")
        self._rainbow_table_attack(done_queue)

        while not done_queue.empty():
            result = done_queue.get()
            if "FOUND" in result:
                print(result)
                return  # Exit if the password is found in the rainbow table

        print("Rainbow Table Attack failed. Switching to John the Ripper...")

        # 3. If both dictionary and rainbow table attacks fail, try John the Ripper
        if self._run_john_the_ripper():
            return  # Exit if John the Ripper finds the password

        print("John the Ripper failed. Starting brute-force attack...")

        # 4. If all else fails, fall back to brute-force
        length = 1
        while length <= max_length and time.time() - start_time < timeout:
            print(f"Trying password length: {length}")
            for _ in range(workers):
                p = multiprocessing.Process(target=self._attempt_crack, args=(length, done_queue))
                processes.append(p)
                p.start()

            for p in processes:
                p.join()

            while not done_queue.empty():
                result = done_queue.get()
                if "FOUND" in result:
                    print(result)
                    return  # Exit if the password is found via brute-force

            length += 1
            processes.clear()

        print("Password not found within the given limit.")

if __name__ == "__main__":
    Cracker.print_banner()  # Print the banner at the start
    user_hash = input("Enter the hash to be cracked: ").strip().lower()
    hash_type = Cracker._detect_hash_type(user_hash)

    if hash_type is None:
        print("Unsupported hash type!")
    else:
        print(f"Detected hash type: {hash_type}")
        charset = string.ascii_lowercase + string.digits + string.punctuation
        
        # Load rainbow table
        cracker = Cracker(hash_type, user_hash, charset)
        cracker.load_rainbow_table('rainbowtabelJsonfile')  # Specify the correct path to your rainbow table
        cracker.start_cracking(workers=4, max_length=30, timeout=600)
