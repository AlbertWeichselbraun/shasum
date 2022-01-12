#!/usr/bin/env python

"""
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
"""

import curses
from argparse import ArgumentParser
from collections import namedtuple
from datetime import datetime, timedelta
from hashlib import sha1
from itertools import cycle
from os import stat
from pathlib import Path
from signal import signal, SIGWINCH
from subprocess import check_output, run
from time import strptime, strftime, localtime
from xattr import xattr


READ_BUFFER_SIZE = 1024*1024*8
XATTR_KEY_HASH = 'user.sha1'
XATTR_KEY_DATE = 'user.sha1date'

Stats = namedtuple('Stats', 'new completed errors')


def shellquote(s):
    return "'" + s.replace("'", "'\\''") + "'"


class CursesUi:

    def __init__(self, stdscr, total_items):
        self.stdscr = stdscr
        self.scanned_items = 0
        self.err_items = 0
        self.total_items = total_items
        self.init_gui()
        self.window_buffer = Stats(new=[], completed=[], errors=[])
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
        # initialize gui
        self.update_progress(done=0, error=0)

    def resize_handler(self, signum, frame):
        curses.update_lines_cols()
        curses.endwin()
        self.init_gui()

    @staticmethod
    def cursor():
        for cursor in cycle('\\|/-'):
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
        cur_window_buffer = getattr(self.window_buffer, window_name)
        cur_window_buffer.append(fname)

        # enforce max_y size
        while len(cur_window_buffer) >= max_y:
            cur_window_buffer.pop(0)

        window.erase()
        for no, fname in enumerate(reversed(cur_window_buffer)):
            window.addstr(fname[-max_x+1:] + "\n")
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

    def end(self):
        curses.endwin()


class FileSystemTree:
    '''
    Provides methods for handling files in a file
    system tree based on the getfattr output.
    '''
    def __init__(self, paths):
        self.files = self.get_files(paths)
        stdscr = curses.initscr()
        self.ui = CursesUi(stdscr, len(self.files))
        signal(SIGWINCH, self.ui.resize_handler)

    def get_files(self, paths):
        # get file list
        files = []
        for root in paths:
            files.extend([MetaDataEntry(fname)
                          for fname in Path(root).rglob('*')
                          if fname.is_file()])
        return files

    def print_duplicates(self):
        print("Checking for duplicates.")

        known_hashes, duplicates = self._get_duplicates()
        for h, dup in duplicates.items():
            print(h, known_hashes[h].fname, "-->",
                  ", ".join([d.fname for d in dup]))

    def print_deduplication_sh(self):
        """ ::returns: a bash script which will replace duplicates
                       with hardlinks """
        print("#!/bin/sh")
        known_hashes, duplicates = self._get_duplicates()
        for h, dup in duplicates.items():
            src = known_hashes[h]
            for d in dup:
                print("ln -f %s %s" % (shellquote(src.fname),
                                       shellquote(d.fname)))

    def _get_duplicates(self):
        """ ::returns: a dictionary with the hash and file
                       objects of all all known_files and of all duplicates """
        known_hashes = {}
        duplicates = {}
        for fobj in self.files:
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
        for fobj in self.files:
            fobj.ui = self.ui
            fobj.update(forced)

    def verify_files(self, min_age):
        min_age = (datetime.now() - timedelta(days=min_age)).timetuple()
        for fobj in self.files:
            fobj.ui = self.ui
            fobj.verify_older(min_age)
        self.ui.end()

        print('\n\n\nSummary')
        print('=======')
        print(f'Total files   : {len(self.files)}')
        print(f'Verified files: {len(self.ui.window_buffer.completed)}')
        print(f'Errors        : {len(self.ui.window_buffer.errors)}\n')
        if len(self.ui.window_buffer.errors):
            print('Faulty files')
            print('============')
            print('\n'.join(self.ui.window_buffer.errors))


class MetaDataEntry:
    """ parses the metadata provided by setfattr and exposes
        it through an object interface.
    """

    DEFAULT_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
    LEGACY_TIME_FORMAT = "%Y-%m-%d"

    def __init__(self, fname: Path):
        self.fname = fname
        self.attrs = xattr(fname)
        self.ui = None

    @staticmethod
    def parse_date(date_str: str):
        """
        Return the datetime object for the given date string.
        """
        if b':' in date_str:
            return strptime(date_str.decode(),
                            MetaDataEntry.DEFAULT_TIME_FORMAT)

        return strptime(date_str.decode(), MetaDataEntry.LEGACY_TIME_FORMAT)

    def sha(self):
        """
        A memory friendly function for computing the shasum of a file.

        Args:
            fname: path of the file for which the checksum should be
            computed.

        Returns:
            computes the file's shaname
        """
        fhash = sha1()
        with self.fname.open('rb') as f:
            while chunk := f.read(READ_BUFFER_SIZE):
                fhash.update(chunk)
                self.ui.update_spin()

        return fhash.hexdigest().encode()

    def update_hash_time(self):
        """
        Update the sha1date to now.

        This method is called after computing or verifying the file's hash.
        """
        self.attrs[XATTR_KEY_DATE] = strftime(self.DEFAULT_TIME_FORMAT,
                                             localtime()).encode('utf8')

    def update(self, force=False):
        """ updates the shasum of the given file
            @param force: whether to force an update of files with existing
                          shasums
        """
        if not force and XATTR_KEY_HASH in self.attrs:
            self.ui.update_progress()
            return

        self.ui.set_current_file(str(self.fname))
        # serialize changes
        self.attrs[XATTR_KEY_HASH] = self.sha()
        self.update_hash_time()
        self.ui.update_progress()

    def verify(self):
        """ verifies the sha sum and updates the sha1date value accordingly"""
        if XATTR_KEY_HASH not in self.attrs:
            self.update(force=True)
            return

        self.ui.set_current_file(str(self.fname))
        if self.sha() == self.attrs[XATTR_KEY_HASH]:
            self.update_hash_time()
            self.ui.add_file("completed", str(self.fname))
            self.ui.update_progress()
        else:
            self.ui.add_file("errors", str(self.fname))
            self.ui.update_progress(error=1)

    def verify_older(self, min_date):
        """ Verifies the shasum of the file, if it is older than
            min_date or does not exist."""
        try:
            if self.parse_date(self.attrs[XATTR_KEY_DATE]) > min_date:
                return
        except KeyError:
            pass

        self.verify()


def get_arguments():
    parser = ArgumentParser(description='Compute shasums')
    parser.add_argument('path', metavar='path', type=str, nargs='+',
                        help='Path for computing checksums')
    parser.add_argument('--verify', metavar='age', type=int, default=180,
                        help='Verify the shasums of all files with a last '
                             'sha1date older than age days (default: 180).')
    parser.add_argument('--compute', action='store_true',
                        help='Compute the shasum of all new files.')
    parser.add_argument('--update', metavar='age', type=int, default=180,
                        help='Verify the shasums of all files with a last '
                             'sha1date older than age days (default: 180).')
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
    """ compares the system's shasum with the internal one. """
    fname = "/etc/passwd"
    assert check_output(['/usr/bin/shasum', fname]).decode("utf8").\
        split()[0] == MetaDataEntry(Path(fname)).sha


# --------------------------------------------------------------------------
# Main program
# --------------------------------------------------------------------------
if __name__ == '__main__':
    args = get_arguments()
    ftree = FileSystemTree(args.path)

    if args.compute:
        ftree.update_files()
    elif args.sha:
        sha_hash = MetaDataEntry(Path(args.path)).sha()
        print(args.path, sha_hash)
    elif args.verify is not None:
        ftree.verify_files(args.verify)
    elif args.print_duplicates:
        ftree.print_duplicates()
    elif args.print_deduplication_sh:
        ftree.print_deduplication_sh()
