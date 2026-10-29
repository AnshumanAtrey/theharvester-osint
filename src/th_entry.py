"""theHarvester, with a deadline on its source phase.

theHarvester awaits every selected source through three queue workers and prints its result lists
only after the last source answers. Its own HTTP timeout is 720 s, so one slow source (crt.sh
stalls on big domains, and it is a default) can hold the whole phase past the run's time limit;
the run is then killed with nothing printed, and there is nothing to deliver.

Run as `python3 -m src.th_entry <theHarvester arguments>`. When TH_SOURCES_DEADLINE (epoch seconds)
is set, each source still searching at that moment is cancelled: theHarvester's worker reports it
as a TimeoutError and moves on, and the other sources' results are printed and saved as usual.
Nothing else about theHarvester changes.
"""
import asyncio
import os
import sys
import time

DEADLINE = float(os.environ.get('TH_SOURCES_DEADLINE') or 0)
_queue_get = asyncio.Queue.get


async def _get_with_deadline(self):
    item = await _queue_get(self)
    # Only theHarvester's per-source coroutines (start.<locals>.store) are put on the deadline.
    if DEADLINE and asyncio.iscoroutine(item) and item.__qualname__.endswith('start.<locals>.store'):
        return asyncio.wait_for(item, max(1.0, DEADLINE - time.time()))
    return item


asyncio.Queue.get = _get_with_deadline

if __name__ == '__main__':
    from theHarvester.theHarvester import main

    sys.argv[0] = 'theHarvester'
    sys.exit(main())
