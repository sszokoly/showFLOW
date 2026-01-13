
import bz2
import glob
import gzip
import os
import re
from datetime import datetime
from glob import glob

def memoize(func):
    """A decorator to cache the return value of func.

    Args:
        func: function to decorate

    Returns:
        wrapper: decorated function
    """
    cache = {}

    def wrapper(args):
        try:
            return cache[args]
        except KeyError:
            cache[args] = func(args)
            return cache[args]
    return wrapper

class Msg(object):
    """Data structure to store trace log message info."""
    __slots__ = ["srcip", "srcport", "dstip", "dstport", "timestamp",
                 "direction", "body", "proto", "method"]

    def __init__(self, srcip="", srcport=None, dstip="", dstport=None,
                 timestamp=None, direction="", body="", proto="", method=""):
        self.srcip = srcip
        self.srcport = srcport
        self.dstip = dstip
        self.dstport = dstport
        self.timestamp = timestamp
        self.direction = direction
        self.body = body
        self.proto = proto
        self.method = method

    def __str__(self):
        return str({k: getattr(self, k) for k in self.__slots__})

class TracesbcSIPReader(object):
    """Generator class which parses tracesbc_sip log files, extracts
    message details and yields Msg class instance.
    """
    LOGDIR = "/archive/log/tracesbc/tracesbc_sip"
    TRACESBCSIP_GLOB = "tracesbc_sip_[1-9][0-9][0-9]*[!_][!_]"

    def __init__(self, logfiles=None, logdir=None, methods=None,
                 ignore_fnu=False):
        """Initializes a TracesbcSIPReader instance.

        Args:
            logfiles (list(str), optional): a collection of tracesbc_sip
                log files to parse, if not provided it starts reading the
                latest tracesbc_sip log in LOGDIR and keep doing it so
                when the log file rotates
            logdir (str): path to directory if tracesbc_sip logs are not
                under the default LOGDIR folder
            methods (list): list of methods to capture
            ignore_fnu (bool): to ignore "off-hook" "ec500" fnu requests

        Returns:
            gen (TracesbcSIPReader): a TracesbcSIPReader generator

        Raises:
            StopIteration: when logfiles is not None and reached the end
                of the last logfile
        """
        self.logdir = logdir or self.LOGDIR
        self.tracesbc_glob = os.path.join(self.logdir, self.TRACESBCSIP_GLOB)
        self.methods = set(methods) if methods else None
        self.ignore_fnu = ignore_fnu

        if logfiles:
            self.logfiles = logfiles
            self.total_logfiles = len(logfiles)
            try:
                self.filename = self.logfiles.pop(0)
            except IndexError:
                raise StopIteration
            self.fd = self.zopen(self.filename)
        else:
            self.total_logfiles = 0
            if not self._is_last_tracesbc_gzipped():
                self.fd = self.zopen(self.filename)
                self.fd.seek(0, 2)

    def __next__(self):
        if self.fd is None:
            if self._is_last_tracesbc_gzipped():
                return None
            self.fd = self.zopen(self.filename)
        readaline = self.fd.readline
        while True:
            line = readaline()
            if not line:
                if self.total_logfiles:
                    self.fd.close()
                    try:
                        self.filename = self.logfiles.pop(0)
                    except IndexError:
                        raise StopIteration
                elif not os.path.exists(self.filename):
                    self.fd.close()
                    if self._is_last_tracesbc_gzipped():
                        return None
                else:
                    return None
                self.fd = self.zopen(self.filename)
                readaline = self.fd.readline
            elif line.startswith("["):
                lines = [line]
                while not lines[-1].startswith("--"):
                    lines.append(readaline().lstrip("\r\n"))

                if self.methods and self._method(lines[2:]) not in self.methods:
                    continue
                if self.ignore_fnu and self._is_fnu(lines[2]):
                    continue

                msg = Msg(**self.splitaddr(lines[1]))
                msg.timestamp = self.strptime(lines[0][1:-3])
                msg.body = "".join(x for x in lines[2:-1] if x)
                msg.method = self._method(lines)
                return msg

    def __iter__(self):
        return self

    def next(self):
        return self.__next__()

    def last_tracesbc_sip(self):
        """str: Returns the last tracesbc_sip log file."""
        return max(glob(self.tracesbc_glob))

    def _is_last_tracesbc_gzipped(self):
        """bool: Return True if last tracesbce_sip is gzipped."""
        self.filename = self.last_tracesbc_sip()
        if self.filename.endswith(".gz"):
            self.fd = None
            return True
        return False

    @property
    def progress(self):
        """int: Returns the percentage of processed logfiles."""
        if self.total_logfiles:
            return int(100-(len(self.logfiles)/float(self.total_logfiles)*100))
        return 100

    @staticmethod
    @memoize
    def splitaddr(line):
        """Parses line argument which contains the source and destination
        host IP address, transport port numbers, protocol type and message
        direction. To speed up processing @memoize caches previous responses.

        Args:
            line (str): log line containing IP address and port info

        Returns:
            dict: {"direction": <str direction>, "srcip": <str srcip>,
                   "srcport": <str srcport>, "dstip": <str dstip>,
                   "dstport": <str dstport>, "proto": <str proto>}
        """
        pattern = r"(IN|OUT): ([0-9.]*):(\d+) --> ([0-9.]*):(\d+) \((\D+)\)"
        keys = ("direction", "srcip", "srcport", "dstip", "dstport", "proto")
        m = re.search(pattern, line)
        try:
            return dict((k, v) for k, v in zip(keys, m.groups()))
        except:
            return dict((k, None) for k in keys)

    @staticmethod
    def _method(lines):
        """Returns SIP message method from CSeq line.

        Args:
            lines (list): list of SIP message lines

        Returns:
            str: SIP method or empty str
        """
        try:
            hdr = next(x for x in lines if x.startswith("CSeq"))
            if hdr:
                params = hdr.split()
                if len(params) == 3:
                    return params[2]
            return ""
        except StopIteration:
            return ""

    @staticmethod
    def _is_fnu(line):
        return ("avaya-cm-fnu=off-hook" in line or
                "avaya-cm-fnu=ec500" in line)

    @staticmethod
    def strptime(s):
        """Converts SSYNDI timestamp to datetime object.

        Note:
            This is 6 times faster than datetime.strptime()

        Args:
            s (str): SSYNDI timestamp

        Returns:
            datetime obj: datetime object
        """
        return datetime(int(s[6:10]), int(s[0:2]), int(s[3:5]), int(s[11:13]),
                        int(s[14:16]), int(s[17:19]), int(s[20:26]))

    @staticmethod
    def zopen(filename):
        """Return file handle depending on file extension type:

        Args:
            filename (str): name of the logfile including path

        Returns:
            obj: file handler
        """
        if filename.endswith(".gz"):
            return gzip.open(filename)
        elif filename.endswith(".bz2"):
            return bz2.BZ2File(filename)
        else:
            return open(filename)