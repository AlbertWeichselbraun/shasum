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
Copyrights 2011-2020 by Albert Weichselbraun <albert@weichselbraun.net>

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
from subprocess import check_output, run
from time import strptime, strftime, localtime
from datetime import datetime, timedelta
from os import stat
from hashlib import sha1
from functools import partial
import curses
from signal import signal, SIGWINCH


READ_BUFFER_SIZE = 1024*1024*8


def shellquote(s):
    return "'" + s.replace("'", "'\\''") + "'"


class CursesUi():

    def __init__(self, stdscr, total_items):
        self.stdscr = stdscr
        self.scanned_items = 0
        self.err_items = 0
        self.total_items = total_items
        self.init_gui()
        self.window_buffer = {'completed': [],
                              'errors': []}
        self.spinner = self.cursor()

    def init_gui(self):
        max_y, max_x = self.stdscr.getmaxyx()
        nlines_file_windows = (max_y - 7) // 2
        ncols_file_windows = max_x - 3

        self.stdscr.clear()
        self.stdscr.border()
        self.stdscr.addstr(1, 1, "shasum.py",
                           curses.COLOR_YELLOW)

        # status windows
        self.win_status_files = self.stdscr.subwin(1, ncols_file_windows,
                                                   3, 1)
        self.win_status_err = self.stdscr.subwin(1, ncols_file_windows,
                                                 4 + nlines_file_windows, 1)
        self.win_progress = self.stdscr.subwin(1, ncols_file_windows,
                                               5 + 2 * nlines_file_windows, 1)

        # file windows
        self.win_current_file = self.stdscr.subwin(1,
                                                   ncols_file_windows,
                                                   4, 2)
        self.win_spin = self.stdscr.subwin(1, 2,
                                           4, 2)
        self.win_completed_files = self.stdscr.subwin(nlines_file_windows - 1,
                                                      ncols_file_windows,
                                                      5, 2)
        self.win_errors = self.stdscr.subwin(nlines_file_windows,
                                             ncols_file_windows,
                                             5 + nlines_file_windows, 2)

        self.stdscr.refresh()

    def resize_handler(self, signum, frame):
        curses.update_lines_cols()
        curses.endwin()
        self.init_gui()

    @staticmethod
    def cursor():
        while True:
            for cursor in "\\|/-":
                yield cursor

    def set_current_file(self, fname):
        _, max_x = self.win_current_file.getmaxyx()
        self.win_current_file.erase()
        self.win_current_file.addstr(fname[-(max_x-2):] + " ")
        y, x = [sum(t) for t in zip(self.win_current_file.getyx(),
                                    self.win_current_file.getparyx())]
        self.win_spin = self.stdscr.subwin(1, 2, y, x)
        self.win_spin.addstr(0, 0, "-")
        self.win_current_file.refresh()
        self.win_spin.refresh()

    def clear_current_file(self):
        self.win_current_file.erase()

    def add_file(self, window_name, fname):
        window = self.win_completed_files if window_name == \
            'completed' else self.win_errors
        max_y, max_x = window.getmaxyx()
        cur_window_buffer = self.window_buffer[window_name]
        cur_window_buffer.append(fname)

        # enforce max_y size
        if len(cur_window_buffer) >= max_y:
            cur_window_buffer.pop(0)

        window.erase()
        for no, fname in enumerate(reversed(cur_window_buffer)):
            if no >= window.getmaxyx()[0]-1:
                break
            window.addstr(fname[-window.getmaxyx()[1]:] + "\n")
        window.refresh()

    def update_spin(self):
        self.win_spin.addstr(0, 0, next(self.spinner))
        self.win_spin.refresh()

    def update_progress(self, done=1, error=0):
        self.scanned_items += done
        self.err_items += error

        self.win_status_files.erase()
        self.win_status_files.addstr(0, 0,
                                     "Files: {}/{}".format(self.scanned_items,
                                                           self.total_items))
        self.win_status_err.erase()
        self.win_status_err.addstr(0, 0,
                                   "Errors: {}/{}".format(self.err_items,
                                                          self.total_items))

        _, max_x = self.win_progress.getmaxyx()
        percent = self.scanned_items / self.total_items

        done = "#" * int((max_x - 20) * percent)
        todo = "." * ((max_x - 20) - len(done))
        self.win_progress.erase()
        self.win_progress.addstr(
            "Progress: [{}{}] ({:>3}%)".format(done, todo,
                                               int(round(percent * 100, 0))))
        self.win_progress.refresh()

        self.win_status_files.refresh()
        self.win_status_err.refresh()


class FileSystemTree(object):
    '''
    Provides methods for handling files in a file
    system tree based on the getfattr output.
    '''
    def __init__(self, root="/"):
        self.files = self.get_files(root)

    def get_files(self, root):
        # get file list
        files = {fname: MetaDataEntry(fname)
                 for fname in check_output(["find", root, "-type", "f"])
                 .decode("utf8").strip().split("\n")}

        # update metadata, if required
        getfattr_output = check_output(["getfattr", "-R", "-d",
                                        "--absolute-names", root]) \
            .decode("utf8").replace("//", "/")
        if getfattr_output:
            for fobj in self.parse_facl_output(getfattr_output):
                files[fobj.fname] = fobj
        return files

    def print_duplicates(self):
        print("Checking for duplicates.")

        known_hashes, duplicates = self._get_duplicates()
        for h, dup in duplicates.items():
            print(h, known_hashes[h].fname, "-->",
                  ", ".join([d.fname for d in dup]))

    def print_deduplication_sh(self):
        ''' ::returns: a bash script which will replace duplicates
                       with hardlinks '''
        print("#!/bin/sh")
        known_hashes, duplicates = self._get_duplicates()
        for h, dup in duplicates.items():
            src = known_hashes[h]
            for d in dup:
                print("ln -f %s %s" % (shellquote(src.fname),
                                       shellquote(d.fname)))

    def _get_duplicates(self):
        ''' ::returns: a dictionary with the hash and file
                       objects of all all known_files and of all duplicates '''
        known_hashes = {}
        duplicates = {}
        for fobj in self.files.values():
            if fobj.sha_hash is None:
                continue

            # only consider duplicates that are not already hardlinked :)
            if fobj.sha_hash in known_hashes \
                    and stat(fobj.fname).st_nlink == 1:
                duplicates[fobj.sha_hash] = duplicates.get(fobj.sha_hash,
                                                           set())
                duplicates[fobj.sha_hash].add(fobj)
            else:
                known_hashes[fobj.sha_hash] = fobj

        return known_hashes, duplicates

    def update_files(self, forced=False):
        stdscr = curses.initscr()
        self.ui = CursesUi(stdscr, len(self.files.values()))
        signal(SIGWINCH, self.ui.resize_handler)
        for fobj in self.files.values():
            fobj.ui = self.ui
            fobj.update(forced)
            self.ui.update_progress()

    def verify_files(self, min_age):
        stdscr = curses.initscr()
        self.ui = CursesUi(stdscr, len(self.files.values()))
        signal(SIGWINCH, self.ui.resize_handler)
        min_age = (datetime.now() - timedelta(days=min_age)).timetuple()
        for fobj in self.files.values():
            fobj.ui = self.ui
            fobj.verify_older(min_age)
            self.ui.update_progress()

    def parse_facl_output(self, output):
        ''' parses the output of getattr
            # file: path + fname
            user.sha1="0000000000000000000000000000000000000000"
            user.sha1date="2013-06-02"
        '''
        sha_hash = None
        sha_date = None
        for line in output.split("\n"):
            if line.startswith("# file:"):
                fname = line.split("# file: ")[1]
                continue
            elif line.startswith("user.sha1="):
                sha_hash = line.split("user.sha1=")[1].replace("\"", "")
            elif line.startswith("user.sha1date="):
                sha_date_str = line.split("user.sha1date=")[1].replace("\"",
                                                                       "")
                if ':' in sha_date_str:
                    sha_date = strptime(sha_date_str,
                                        MetaDataEntry.DEFAULT_TIME_FORMAT)
                else:
                    sha_date = strptime(sha_date_str,
                                        MetaDataEntry.LEGACY_TIME_FORMAT)

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

    def sha(self, fname):
        '''
        A memory friendly function for computing the shasum of a file.
        ::param: fname
        ::return:
            computes the file's shaname
        '''
        fhash = sha1()
        with open(fname, 'rb') as f:
            for chunk in iter(partial(f.read, READ_BUFFER_SIZE), b''):
                fhash.update(chunk)
                self.ui.update_spin()

        return fhash.hexdigest()

    def update(self, force=False):
        ''' updates the shasum of the given file
            @param force: whether to force an update of files with existing
                          shasums
        '''
        if self.sha_hash and not force:
            self.ui.update_progress()
            return

        self.ui.set_current_file(self.fname)

        self.sha_hash = self.sha(self.fname)
        self.sha_date = localtime()
        # serialize changes
        self._write(self.fname, 'user.sha1', self.sha_hash)
        self._write(self.fname, 'user.sha1date', strftime(
            self.DEFAULT_TIME_FORMAT, self.sha_date))

    def verify(self):
        ''' verifies the sha sum and updates the sha1date value accordingly'''
        if not self.sha_hash:
            self.update()
            return

        self.ui.set_current_file(self.fname)
        sha_content = self.sha(self.fname)
        if sha_content == self.sha_hash:
            self.sha_date = localtime()
            self._write(self.fname, 'user.sha1date', strftime(
                self.DEFAULT_TIME_FORMAT, self.sha_date))
            self.ui.add_file("completed", self.fname)
        else:
            self.ui.add_file("errors", self.fname)

    def verify_older(self, min_date):
        ''' verifies the shasum of the file if it is older than
            min_date '''
        if not self.sha_date or self.sha_date < min_date:
            self.verify()

    @staticmethod
    def _write(fname, attr, value):
        run(["setfattr", "-n", attr, "-v", value, fname])

    def __str__(self):
        return f"{self.fname} ({self.sha_hash}, {self.sha_date})"


def get_arguments():
    parser = ArgumentParser(description='Compute shasums')
    parser.add_argument('path', metavar='path', type=str,
                        help='Path for computing checksums')
    parser.add_argument('--verify', metavar='age', type=int, default=180,
                        help='Verify the shasums of all files with a last '
                             'sha1date older than age days (default: 180).')
    parser.add_argument('--compute', action='store_true',
                        help='Compute the shasum of all new files.')
    parser.add_argument('--sha', action='store_true',
                        help='Computes the SHA sum of the given file.')
    parser.add_argument('--print-duplicates', action='store_true',
                        help='Compute duplicates.')
    parser.add_argument('--print-deduplication-sh', action='store_true',
                        help='Returns a shell script which replaces '
                             'duplicates with hard links.')
    return parser.parse_args()


# --------------------------------------------------------------------------
# Unit tests
# --------------------------------------------------------------------------
def test_shasum():
    ''' compares the system's shasum with the internal one. '''
    fname = "/etc/passwd"
    assert check_output(['/usr/bin/shasum', fname]).decode("utf8").\
        split()[0] == MetaDataEntry().sha(fname)


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
