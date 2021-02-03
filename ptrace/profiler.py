from profile import Profile
from os import unlink
from io import StringIO
import pstats


def calibrate(n):
    """
    https://docs.python.org/3/library/profile.html#calibration
    """
    if n > 0:
        pr = Profile()
        magics = []
        for i in range(n):
            magics.append(pr.calibrate(10000))
        return sum(magics) / n


def runProfiler(logger, func, args=tuple(), kw={},
                verbose=True, nb_func=25,
                sort_by=('time',), nb_cal=0):
    """
    Run a function in a profiler and then display the functions sorted by time.
    """
    profile_filename = "/tmp/profiler"
    prof = Profile(bias=calibrate(nb_cal))
    try:
        logger.warning("Run profiler")
        result = prof.runcall(func, *args, **kw)
        logger.error("Profiler: Process data...")
        prof.dump_stats(profile_filename)
        stat = pstats.Stats(prof)
        stat.strip_dirs()
        stat.sort_stats(*sort_by)

        logger.error("Profiler: Result:")
        log = StringIO()
        stat.stream = log
        stat.print_stats(nb_func)
        log.seek(0)
        for line in log:
            logger.error(line.rstrip())
        return result
    finally:
        unlink(profile_filename)
