#!/usr/bin/env python

from argparse import ArgumentParser
from subprocess import Popen, PIPE
from hashlib import sha1
from time import strptime, strftime, localtime

from sys import stderr

class FileSystemTree(object):

    def __init__(self, root="/"):
        self.files = self.get_files( root ) 


    def get_files(self, root):
        # get file list
        files = { fname: MetaDataEntry(fname) for fname \
                  in Popen(["find", root, "-type", "f" ], stdout=PIPE).communicate()[0].strip().split("\n") }

        # update metadata, if required
        getfattr_output = Popen(["getfattr", "-R", "-d", "--absolute-names",  root], stdout=PIPE).communicate()[0].replace("//", "/")
        for fobj in self.parse_facl_output( getfattr_output ):
            files[fobj.fname] = fobj
        return files


    def print_duplicates(self):
        known_hashes = {}
        duplicates = {}
        print "Checking for duplicates in %d files." % (len(self.files))
        for fobj in self.files.values():
            if fobj.sha_hash is None:
                continue

            if fobj.sha_hash in known_hashes:
                duplicates[fobj.sha_hash] = duplicates.get(fobj.sha_hash, set())
                duplicates[fobj.sha_hash].add(fobj)
                duplicates[fobj.sha_hash].add( known_hashes[fobj.sha_hash] )
            else:
                known_hashes[fobj.sha_hash] = fobj
        
        for h, dup in duplicates.items():
            print h, ", ".join( [d.fname for d in dup] )
           

    def update_files(self, forced=False):
        for fobj in self.files.values():
            fobj.update(forced)


    def verify_files(self):
        for fobj in self.files.values():
            fobj.verify()


    def parse_facl_output(self, output):
        """ parses the output of getattr 
            # file: path + fname
            user.sha1="0000000000000000000000000000000000000000"
            user.sha1date="2013-06-02"
        """
        if not output:
            raise StopIteration

        sha_hash = None
        sha_date = None
        for line in output.split("\n"):
            if line.startswith("# file:"):
                fname = line.split("# file: ")[1]
                continue
            elif line.startswith("user.sha1="):
                sha_hash = line.split("user.sha1=")[1].replace("\"", "")
            elif line.startswith("user.sha1date="):
                sha_date_str = line.split("user.sha1date=")[1].replace("\"", "")
                if ':' in sha_date_str:
                    sha_date = strptime(sha_date_str, MetaDataEntry.DEFAULT_TIME_FORMAT)
                else:
                    sha_date = strptime(sha_date_str, MetaDataEntry.LEGACY_TIME_FORMAT)

            elif line.strip()=="" and sha_hash and sha_date:
                yield MetaDataEntry(fname, sha_hash, sha_date)
                sha_hash = None
                sha_date = None



    
class MetaDataEntry(object):

    DEFAULT_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
    LEGACY_TIME_FORMAT  = "%Y-%m-%d"
    
    def __init__(self, fname, sha_hash=None, sha_date=None):
        self.fname   = fname
        self.sha_hash = sha_hash
        self.sha_date = sha_date

    def update(self, force=False):
        """ updates the shasum of the given file 
            @param force: whether to force an update of files with existing
                          shasums 
        """
        if self.sha_hash and not force:
            return

        print "Computing SHASUM for '%s'" % (self.fname)
        self.sha_hash = sha1( open(self.fname).read() ).hexdigest()
        self.sha_date = localtime()
        # serialize changes
        self._write(self.fname, 'user.sha1', self.sha_hash)
        self._write(self.fname, 'user.sha1date', strftime(self.DEFAULT_TIME_FORMAT, self.sha_date))

    def verify(self):
        """ verifies the sha sum and updates the sha1date value accordingly"""
        if not self.sha_hash:
            self.update()
            return 
        print "Verifying SHASUM for '%s'" % (self.fname), 
        sha_content = sha1( open(self.fname).read() ).hexdigest()
        if sha_content == self.sha_hash:
            self.sha_date = localtime()
            self._write(self.fname, 'user.sha1date', strftime(self.DEFAULT_TIME_FORMAT, self.sha_date))
            print "OK"
        else:
            stderr.write("INCORRECT! - expected: '%s' but got '%s'!\n" % (self.fname, self.sha_hash, sha_content))

    def verify_older(self, min_date):
        """ verifies the shasum of the file if it is older than
            min_date """
        if self.sha_date < min_date:
            self.verify()

    @staticmethod
    def _write(fname, attr, value):
        Popen(["setfattr", "-n", attr, "-v", value, fname], stdout=PIPE).communicate()[0]

    def __str__(self):
        return "%s (%s, %s)" % (self.fname, self.sha_hash, self.sha_date)


def get_arguments():
    parser = ArgumentParser(description='Compute shasums')
    parser.add_argument('path', metavar='path', type=str, 
                         help='Path for computing checksums')
    parser.add_argument('-verify', action='store_true', 
                         help='Verify the shasums of all files.')
    parser.add_argument('-compute', action='store_true',
                         help='Compute the shasum of all new files.')
    parser.add_argument('-print-duplicates', action='store_true',
                         help='Compute duplicates.')
    #parser.add_argument('verify-date', type=str,
    #                     help='Verify all files that have not been verified since verify-date.')
    return parser.parse_args()


if __name__ == '__main__':
    args = get_arguments()
    f = FileSystemTree( args.path )
    
    if args.compute:
        f.update_files()
    elif args.verify:
        f.verify_files()
    elif args.print_duplicates:
        f.print_duplicates()




    
