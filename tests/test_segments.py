import sys
import os
import time
import signal
import random
import shutil
import struct
import hashlib
import string

class App ():
    def __init__(self):
        self.read_pid = None
        self.write_pid = None
        self.tmp_dir = "/tmp/orig/"
        self.write_dir = "/tmp/write/"
        self.read_dir = "/tmp/read/"
        self.nr_tests = 10
        self.l_files = []
        random.seed (time.time())

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
        except:
            None
        try:
            os.mkdir (self.read_dir);
        except:
            None
        try:
            os.mkdir (self.tmp_dir);
        except:
            None

        try:
            unmount (self.write_dir)
            unmount (self.read_dir)
        except:
            None

        #self.write_pid = self.start_hydrafs (self.write_dir)
        #self.read_pid = self.start_hydrafs (self.read_dir)

        self.create_files ()

        print self.l_files

        #time.sleep (5)
        
        try:
            os.kill (self.write_pid, signal.SIGINT)
            os.kill (self.read_pid, signal.SIGINT)
        except:
            None

        try:
            unmount (self.write_dir)
            unmount (self.read_dir)
        except:
            None

        shutil.rmtree (self.write_dir)
        shutil.rmtree (self.read_dir)
        #shutil.rmtree (self.tmp_dir)


    def create_file (self, fname, flen):
        fout = open (fname, 'w')
        fout.write (os.urandom (flen))
        fout.close ()

    def md5_for_file (self, fname, block_size=2**20):
        fout = open (fname, 'r')
        md5 = hashlib.md5()
        while True:
            data = fout.read(block_size)
            if not data:
                break
            md5.update(data)
        fout.close ()
        return md5.hexdigest()

    def str_gen (self, size=10, chars=string.ascii_uppercase + string.digits):
        return ''.join (random.choice(chars) for x in range(size))

    def create_files (self):

        # small files < 5mb
        for i in range (0, self.nr_tests):
            fname = self.str_gen ()
            flen = random.randint (1, 1024 * 1024 * 5)
            self.create_file (self.tmp_dir + fname, flen)
            self.l_files.append ({"name":self.tmp_dir + fname, "len": flen, "md5": self.md5_for_file (self.tmp_dir + fname)})

        # medium files 6mb - 20mb
        for i in range (0, self.nr_tests):
            fname = self.str_gen ()
            flen = random.randint (1024 * 1024 * 6, 1024 * 1024 * 20)
            self.create_file (self.tmp_dir + fname, flen)
            self.l_files.append ({"name":self.tmp_dir + fname, "len": flen, "md5": self.md5_for_file (self.tmp_dir + fname)})
        
        # large files 30mb - 40mb
        for i in range (0, self.nr_tests):
            fname = self.str_gen ()
            flen = random.randint (1024 * 1024 * 30, 1024 * 1024 * 40)
            self.create_file (self.tmp_dir + fname, flen)
            self.l_files.append ({"name":self.tmp_dir + fname, "len": flen, "md5": self.md5_for_file (self.tmp_dir + fname)})


if __name__ == "__main__":
    app = App ()
    app.run ()
