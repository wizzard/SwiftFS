import sys
import os
import time
import signal

tries = 10

def md5_for_file (f, block_size=2**20):
    md5 = hashlib.md5()
    while True:
        data = f.read(block_size)
        if not data:
            break
        md5.update(data)
    return md5.digest()

def run_test ():
    pid = os.fork()
    if pid == 0:
        base_path = os.path.join(os.path.dirname(__file__), '..')
        bin_path = os.path.join(base_path, "src")
        args = [os.path.join(bin_path, "hydrafs"), "-v", "-f", "http://10.0.0.104:8080/auth/v1.0", "cont1", "mnt"]
        os.execv(args[0], args)
    else:
        print ("Parent")

if __name__ == "__main__":
    run_test ()
