#!/usr/bin/env python

from argparse import ArgumentParser
from commands import getoutput
from hashlib import sha1
from time import strptime, strftime, time

class FileSystemTree(object):

    def __init__(self, root="/"):
        self.files = self.get_files( root ) 


    def get_files(self, root):
        files = {}
        for fobj in self.parse_facl_output( getoutput("getfattr -Rd --absolute-names %s" % (root)) ):
            files[fobj.fname] = fobj
        return files

    def parse_facl_output(self, output):
        """ parses the output of getattr 
            # file: path + fname
            user.sha1="0000000000000000000000000000000000000000"
            user.sha1date="2013-06-02"
        """
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
                    sha_date = strptime(MetaDataEntry.DEFAULT_TIME_FORMAT, sha_date_str)
                else:
                    sha_date = strptime(MetaDataEntry.LEGACY_TIME_FORMAT, sha_date_str)

            elif line.strip()=="":
                yield MetaDataEntry(fname, sha_hash, sha_date)
                sha_hash = None
                sha_date = None

    
class MetaDataEntry(object):

    DEFAULT_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
    LEGACY_TIME_FORMAT  = "%Y-%m-%d"
    
    def __init__(self, fname, sha_hash, sha_date):
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

        self.sha_hash = sha1( open(self.fname).read() ).hexdigest()
        self.sha_date = time()
        # serialize changes
        self._write(self.fname, 'sha1', self.sha_hash)
        self._write(self.fname, 'sha1date', strftime(self.DEFAULT_TIME_FORMAT, self.sha_date))

    def verify(self):
        """ verifies the sha sum and updates the sha1date value accordingly"""
        sha_content = sha1( open(self.fname).read() ).hexdigest()
        if sha_content == self.sha_hash:
            self.sha_date = time()
            self._write(self.fname, 'sha1date', strftime(self.DEFAULT_TIME_FORMAT, self.sha_date))
        else:
            print "INCORRECT sha hash for '%s' - expected: '%s' but got '%s'!" % (self.fname, self.sha_hash, sha_content)

    def verify_older(self, min_date):
        """ verifies the shasum of the file if it is older than
            min_date """
        if self.sha_date < min_date:
            self.verify()

    @staticmethod
    def _write(fname, attr, value):
        getoutput("setfattr -n %s -v %s \"%s\"" % (attr, value, fname))

    def __str__(self):
        return "%s (%s, %s)" % (self.fname, self.sha_hash, self.sha_date)


def get_arguments():
    parser = ArgumentParser(description='Compute shasums')
    parser.add_argument('path', metavar='path', type=str, 
                         help='Path for computing checksums')
    return parser.parse_args()


if __name__ == '__main__':
    args = get_arguments()
    f = FileSystemTree( args.path )


    
