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

class App ():
    def __init__(self):
        self.read_pid = None
        self.write_pid = None
        self.write_dir = "/tmp/write/"
        self.read_dir = "/tmp/read/"

    def start_hydrafs (self, mnt_dir):
        pid = os.fork()
        if pid == 0:
            base_path = os.path.join(os.path.dirname(__file__), '..')
            bin_path = os.path.join(base_path, "src")
            args = [os.path.join(bin_path, "hydrafs"), "-v", "-f", "--disable_cache", "--disable_stats", "http://10.0.0.104:8080/auth/v1.0", "cont1", mnt_dir]
            os.execv(args[0], args)
        else:
            return pid

    def unmount (self, mnt_dir):
        pid = os.fork()
        if pid == 0:
            args = ["fusermount", "-u", mnt_dir]
            os.execv(args[0], args)


    def run (self):
        try:
            os.mkdir (self.write_dir);
            os.mkdir (self.read_dir);
        except:
            None

        try:
            unmount (self.write_dir)
            unmount (self.read_dir)
        except:
            None

        self.write_pid = self.start_hydrafs (self.write_dir)
        self.read_pid = self.start_hydrafs (self.read_dir)

        self.check_files ()

        time.sleep (5)
        os.kill (self.write_pid, signal.SIGINT)
        os.kill (self.read_pid, signal.SIGINT)

    def check_files (self):
        None


if __name__ == "__main__":
    app = App ()
    app.run ()
