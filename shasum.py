#!/usr/bin/env python

'''
shasum.py
-----------------------------------------------------------------------
Computes and stores the shasum of files in file system attributes
and uses them to
 a) verify the file integrity
 b) identifiy duplicate files
 c) hard-link based deduplication
-----------------------------------------------------------------------
Copyrights 2011-2013 by Albert Weichselbraun <albert@weichselbraun.net>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

@author: Albert Weichselbraun <albert@weichselbraun.net>
'''

from argparse import ArgumentParser
from subprocess import Popen, PIPE, check_output
from time import strptime, strftime, localtime
from datetime import datetime, timedelta
from os import stat
from hashlib import sha1
from functools import partial

from sys import stderr

READ_BUFFER_SIZE = 1024*1024
SHELLQUOTE = lambda s: "'" + s.replace("'", "'\\''") + "'"

class FileSystemTree(object):
    '''
    Provides methods for handling files in a file
    system tree based on the getfattr output.
    '''
    def __init__(self, root="/"):
        self.files = self.get_files(root)


    def get_files(self, root):
        # get file list
        files = {fname: MetaDataEntry(fname) for fname in Popen(["find", root, "-type", "f"], stdout=PIPE).communicate()[0].strip().split("\n")}

        # update metadata, if required
        getfattr_output = Popen(["getfattr", "-R", "-d", "--absolute-names", root], stdout=PIPE).communicate()[0].replace("//", "/")
        for fobj in self.parse_facl_output(getfattr_output):
            files[fobj.fname] = fobj
        return files


    def print_duplicates(self):
        print("Checking for duplicates in %d files." % (len(self.files)))

        known_hashes, duplicates = self._get_duplicates()
        for h, dup in duplicates.items():
            print(h, known_hashes[h].fname, "-->", ", ".join([d.fname for d in dup]))

    def print_deduplication_sh(self):
        ''' ::returns: a bash script which will replace duplicates
                       with hardlinks '''
        print("#!/bin/sh")
        known_hashes, duplicates = self._get_duplicates()
        for h, dup in duplicates.items():
            src = known_hashes[h]
            for d in dup:
                print("ln -f %s %s" % (SHELLQUOTE(src.fname), SHELLQUOTE(d.fname)))


    def _get_duplicates(self):
        ''' ::returns: a dictionary with the hash and file
                       objects of all all known_files and of all duplicates '''
        known_hashes = {}
        duplicates = {}
        for fobj in self.files.values():
            if fobj.sha_hash is None:
                continue

            # only consider duplicates that are not already hardlinked :)
            if fobj.sha_hash in known_hashes and stat(fobj.fname).st_nlink == 1:
                duplicates[fobj.sha_hash] = duplicates.get(fobj.sha_hash, set())
                duplicates[fobj.sha_hash].add(fobj)
            else:
                known_hashes[fobj.sha_hash] = fobj

        return known_hashes, duplicates


    def update_files(self, forced=False):
        for fobj in self.files.values():
            fobj.update(forced)


    def verify_files(self, min_age):
        min_age = (datetime.now() - timedelta(days=min_age)).timetuple()
        for fobj in self.files.values():
            fobj.verify_older(min_age)


    def parse_facl_output(self, output):
        ''' parses the output of getattr
            # file: path + fname
            user.sha1="0000000000000000000000000000000000000000"
            user.sha1date="2013-06-02"
        '''
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

            elif line.strip() == "" and sha_hash and sha_date:
                yield MetaDataEntry(fname, sha_hash, sha_date)
                sha_hash = None
                sha_date = None




class MetaDataEntry(object):
    ''' parses the metadata provided by setfattr and exposes
        it through an object interface.
    '''

    DEFAULT_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
    LEGACY_TIME_FORMAT = "%Y-%m-%d"

    def __init__(self, fname, sha_hash=None, sha_date=None):
        self.fname = fname
        self.sha_hash = sha_hash
        self.sha_date = sha_date

    @staticmethod
    def sha(fname):
        '''
        A memory friendly function for computing the shasum of a file.
        ::param: fname
        ::return:
            computes the file's shaname
        '''
        with open(fname) as f:
            fhash = sha1()
            for chunk in iter(partial(f.read, READ_BUFFER_SIZE), ''):
                fhash.update(chunk)

        return fhash.hexdigest()


    def update(self, force=False):
        ''' updates the shasum of the given file
            @param force: whether to force an update of files with existing
                          shasums
        '''
        if self.sha_hash and not force:
            return

        print "Computing SHASUM for '%s'" % (self.fname)

        self.sha_hash = self.sha(self.fname)
        self.sha_date = localtime()
        # serialize changes
        self._write(self.fname, 'user.sha1', self.sha_hash)
        self._write(self.fname, 'user.sha1date', strftime(self.DEFAULT_TIME_FORMAT, self.sha_date))

    def verify(self):
        ''' verifies the sha sum and updates the sha1date value accordingly'''
        if not self.sha_hash:
            self.update()
            return
        print "Verifying SHASUM for '%s'" % (self.fname),
        sha_content = self.sha(self.fname)
        if sha_content == self.sha_hash:
            self.sha_date = localtime()
            self._write(self.fname, 'user.sha1date', strftime(self.DEFAULT_TIME_FORMAT, self.sha_date))
            print "OK"
        else:
            stderr.write("INCORRECT checksum for '%s'! - expected: '%s' but got '%s'!\n" % (self.fname, self.sha_hash, sha_content))

    def verify_older(self, min_date):
        ''' verifies the shasum of the file if it is older than
            min_date '''
        if self.sha_date < min_date:
            self.verify()

    @staticmethod
    def _write(fname, attr, value):
        Popen(["setfattr", "-n", attr, "-v", value, fname], stdout=PIPE).communicate()[0]

    def __str__(self):
        return "%s (%s, %s)" % (self.fname, self.sha_hash, self.sha_date)


def get_arguments():
    parser = ArgumentParser(description='Compute shasums')
    parser.add_argument('path', metavar='path', type=str, help='Path for computing checksums')
    parser.add_argument('--verify', metavar='age', type=int, default=180, help='Verify the shasums of all files with a last sha1date older than age days (default: 180).')
    parser.add_argument('--compute', action='store_true', help='Compute the shasum of all new files.')
    parser.add_argument('--sha', action='store_true', help='Computes the SHA sum of the given file.')
    parser.add_argument('--print-duplicates', action='store_true', help='Compute duplicates.')
    parser.add_argument('--print-deduplication-sh', action='store_true', help='Returns a shell script which replaces duplicates with hard links.')
    return parser.parse_args()


# --------------------------------------------------------------------------
# Unit tests
# --------------------------------------------------------------------------
def test_shasum():
    ''' compares the system's shasum with the internal one. '''
    fname = "/etc/passwd"
    assert check_output(['/usr/bin/shasum', fname]).split()[0] == MetaDataEntry.sha(fname)


# --------------------------------------------------------------------------
# Main program
# --------------------------------------------------------------------------
if __name__ == '__main__':
    args = get_arguments()
    ftree = FileSystemTree(args.path)

    if args.compute:
        ftree.update_files()
    elif args.sha:
        sha = MetaDataEntry.sha(args.path)
        print(args.path, sha)
    elif args.verify is not None:
        ftree.verify_files(args.verify)
    elif args.print_duplicates:
        ftree.print_duplicates()
    elif args.print_deduplication_sh:
        ftree.print_deduplication_sh()

