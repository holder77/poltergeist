#DESCRIPTION: This file is the bridge between "a button was clicked" and
#             "a backend function (which just calls print()) is running
#             on some other thread." None of Poltergeist's existing check
#             modules know or care whether they're being driven by the
#             text menu or this GUI - they still just call print() and
#             log.add(). This file captures that printed output live and
#             hands it to the GUI's on-screen console pane, WITHOUT ever
#             letting a background thread touch a Tkinter widget directly
#             (Tkinter only tolerates being driven from its own main
#             thread - touching a widget from a worker thread is a real
#             source of crashes, so this file is careful never to do
#             that). Nothing in this file imports Tkinter at all, which
#             means every class here can be exercised by a plain unit
#             test even on a machine with no display.

#import sys so we can temporarily swap out sys.stdout while an action runs.
import sys

#import threading so backend actions (which can take seconds, like an SSH
#deploy, or run forever, like Sentinel: Monitor) run on their own thread
#instead of freezing the whole window while they work.
import threading

#import queue for the one thread-safe hand-off point between a background
#thread (which only ever puts things into the queue) and the GUI's own
#main-thread polling loop (which is the only thing that ever takes things
#back out), so this file never has to coordinate locking by hand.
import queue

#import traceback so an unexpected error inside a background action gets
#captured in full, instead of silently vanishing on a thread nobody is
#watching (this is a real risk on Windows if the GUI was double-clicked
#rather than launched from a terminal - there may be no console at all
#for a stray traceback to even print to).
import traceback


#Define ConsoleRedirect, a small file-like stand-in for sys.stdout. Any
#code that calls print() while this object is swapped in as sys.stdout
#ends up here instead of (or as well as) the real terminal. It only
#needs to support write() and flush() to behave like a real stream.
class ConsoleRedirect:
    #Define the constructor. output_queue is where every write() call's
    #text lands; also_write_to is an optional second real stream (the
    #ORIGINAL sys.stdout, captured before this object replaced it) so
    #anyone running the GUI from an existing terminal still sees the
    #output there too, instead of it only ever appearing in the window.
    def __init__(self, output_queue, also_write_to=None):
        #Remember the queue every piece of text gets pushed onto.
        self.output_queue = output_queue
        #Remember the optional second destination for the same text.
        self.also_write_to = also_write_to

    #Define write, called by print() (and anything else) for every chunk
    #of text it produces.
    def write(self, text):
        #Only bother queuing non-empty text; print() calls write("\n")
        #and write("") in ways that would otherwise clutter the queue
        #with a lot of pointless near-empty entries.
        if text:
            #Hand the text to the queue. put() on a plain queue.Queue is
            #already thread-safe, so no extra locking is needed here.
            self.output_queue.put(text)
        #If a second real stream was given, mirror the same text there.
        if self.also_write_to is not None:
            #Wrap in a try block since a closed or broken terminal stream
            #should never be allowed to crash the action that's printing.
            try:
                #Write the same text to the real terminal too.
                self.also_write_to.write(text)
            #Swallow any failure writing to the mirror stream.
            except Exception:
                #Deliberately do nothing - the GUI's own queue already
                #has the text either way.
                pass

    #Define flush, since some code calls this on whatever sys.stdout is.
    def flush(self):
        #Only the mirrored real stream needs flushing; the queue has no
        #buffering of its own to flush.
        if self.also_write_to is not None:
            #Wrap in a try block for the same reason as write() above.
            try:
                #Flush the real terminal stream.
                self.also_write_to.flush()
            #Swallow any failure flushing the mirror stream.
            except Exception:
                #Deliberately do nothing.
                pass

    #Define isatty. color.py's supports_color() calls sys.stdout.isatty()
    #before colorizing ANY printed finding - and since every live module
    #reports through evidence.py's Log.add(), which colorizes on every
    #single call, that is not a rare code path, it is nearly ALL GUI
    #output. A plain object has no isatty() at all, so without this,
    #the very first colorized line (the first finding, or even just a
    #section header) raises AttributeError and aborts the action, which
    #BackgroundRunner's try/except would hide as a traceback dumped into
    #the console pane instead of real results. Returning False here is
    #also simply correct: this is a queue-backed window pane, not a real
    #terminal, and a Tkinter Text widget does not interpret ANSI escape
    #codes - without this, a "successful" run would show literal
    #"\x1b[91m...\x1b[0m" garbage around every severity label instead of
    #colored text. False makes supports_color() skip colorizing cleanly,
    #which is exactly what both problems need.
    def isatty(self):
        #Never a real terminal, by definition.
        return False


#Define BackgroundRunner, which runs exactly ONE backend action at a time
#on its own thread, capturing its printed output into a shared queue. It
#deliberately refuses to start a second action while one is still running
#- none of Poltergeist's backend modules were written to be safe to run
#concurrently with themselves (they share one findings.jsonl, one
#Tripwire/logging state file, etc.), and the plain text menu never
#allowed overlapping actions either, so this keeps the same "one thing at
#a time" model the rest of the project already relies on.
class BackgroundRunner:
    #Define the constructor.
    def __init__(self, output_queue):
        #Share the same output queue the GUI's console pane is already
        #polling, so a manual click's output and the main window's own
        #ambient auto-scan pass (see gui/app.py's _poll_loop) both land
        #in the same place - there is only ONE kind of background action
        #now, run once and finished, whether a human clicked it or the
        #auto-scan timer started it.
        self.output_queue = output_queue
        #A lock protecting the busy flag, since the flag is read from the
        #main thread (to decide whether a click should be allowed) and
        #written from the background thread (the instant it finishes).
        self._lock = threading.Lock()
        #Whether an action is currently running.
        self._busy = False
        #The most recent action's captured traceback text, or None if it
        #finished without raising. Read once by the GUI after noticing
        #the action finished, then cleared on the next start().
        self.last_error_text = None

    #Define busy as a read-only property so callers cannot accidentally
    #set it directly and desync it from the lock that protects it.
    @property
    def busy(self):
        #Take the lock just long enough to read the flag safely.
        with self._lock:
            #Return the current value.
            return self._busy

    #Define start, which launches fn (a plain zero-argument callable) on
    #a background thread. Returns True if it actually started, or False
    #if another action was already running (the caller should treat a
    #False result as "ignore this click," not as an error).
    def start(self, fn):
        #Take the lock to check-and-set the busy flag as one atomic step,
        #so two near-simultaneous clicks can never both start a thread.
        with self._lock:
            #Refuse to start a second action on top of a running one.
            if self._busy:
                #Tell the caller nothing happened.
                return False
            #Claim the busy flag before releasing the lock.
            self._busy = True
        #Clear out any previous action's leftover error text.
        self.last_error_text = None
        #Remember whatever sys.stdout currently is (the real terminal, if
        #one exists) so the worker thread can restore it afterward and so
        #the redirect below can still mirror output there live.
        previous_stdout = sys.stdout
        #Swap in our queue-backed redirect for the duration of this action.
        sys.stdout = ConsoleRedirect(self.output_queue, also_write_to=previous_stdout)
        #Build and start the actual worker thread. daemon=True means this
        #thread can never, by itself, keep the whole program from exiting.
        worker = threading.Thread(target=self._run, args=(fn, previous_stdout), daemon=True)
        worker.start()
        #Tell the caller the action did start.
        return True

    #Define _run, the function that actually executes on the background
    #thread. It is the ONLY method in this class that runs anywhere but
    #the main thread, and it never touches a Tkinter widget - only the
    #queue (safe) and this object's own plain attributes.
    def _run(self, fn, previous_stdout):
        #Wrap the real call in a broad try/except: an uncaught exception
        #on a background thread would otherwise just vanish (or print to
        #a terminal nobody's watching), which would make the GUI look
        #like it silently did nothing.
        try:
            #Actually run the backend action.
            fn()
        #Catch literally anything that goes wrong inside the action.
        except Exception:
            #Capture the full traceback as text.
            self.last_error_text = traceback.format_exc()
            #Also push a short, readable error line into the console
            #queue itself, so it shows up right in the output pane where
            #the user is already looking, not just in a field they'd
            #have to know to check.
            self.output_queue.put(f"\n[Poltergeist] That action hit an unexpected error - see details below.\n{self.last_error_text}\n")
        #Always run this part, whether or not an exception happened.
        finally:
            #Restore whatever sys.stdout was before this action started,
            #so a second action later doesn't redirect into a redirect.
            sys.stdout = previous_stdout
            #Release the busy flag so the next action is allowed to start.
            with self._lock:
                #Clear the flag.
                self._busy = False


#There used to be a second class here, MonitorController, behind a
#separate "Sentinel: Monitor" toggle button that looped forever on its
#own thread until clicked again. The Stage 1 pivot replaced that with
#the main window's own ambient, continuously-refreshing view instead
#(see gui/app.py's _poll_loop, which just calls BackgroundRunner.start()
#again on a timer) - there is no longer a second, always-looping
#background thread anywhere in this file, only ever the one-shot
#BackgroundRunner above, started either by a click or by that timer.


#Define drain_queue, a tiny shared helper both the console pane and
#anything else watching this queue can use: pull out everything currently
#waiting, without blocking, and hand it back as one list of text chunks.
#Meant to be called from the GUI's own main-thread polling loop.
def drain_queue(output_queue):
    #Start an empty list to collect whatever is waiting right now.
    chunks = []
    #Keep pulling until the queue reports empty.
    while True:
        #Try to grab the next item without waiting for one to appear.
        try:
            #Pull one chunk of text off the queue.
            chunks.append(output_queue.get_nowait())
        #queue.Empty is raised the instant there's nothing left waiting.
        except queue.Empty:
            #Stop the loop; we've drained everything there was.
            break
    #Hand back everything collected.
    return chunks
