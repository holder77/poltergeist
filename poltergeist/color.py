#DESCRIPTION: A tiny, dependency-free ANSI color helper. We deliberately
#             do NOT add a library like colorama just for this - a couple
#             of escape codes is all color-coded terminal output actually
#             needs, and keeping requirements.txt at just psutil matters
#             more than saving a few lines here. Respects the standard
#             NO_COLOR environment variable and turns itself off when
#             output is being piped/redirected rather than watched live.

#import os so we can check environment variables and enable Windows'
#ANSI support.
import os

#import sys so we can check whether stdout is an actual terminal.
import sys

#import platform so we only run the Windows-specific enabling step there.
import platform

#On modern Windows 10+ terminals, printing an empty string through
#os.system("") is a well-known trick that turns on ANSI escape code
#processing for the rest of the process; older terminals simply ignore it.
if platform.system() == "Windows":
    #Enable ANSI escape processing once, at import time.
    os.system("")

#Map each severity/role word we use to its ANSI color escape code.
CODES = {
    "high": "\033[91m",    #bright red
    "medium": "\033[93m",  #bright yellow
    "info": "\033[96m",    #bright cyan
    "header": "\033[95m",  #bright magenta, matches the ghost banner's color
    "ok": "\033[92m",      #bright green
    "dim": "\033[90m",     #dim gray, for suggested-fix lines
}
#The reset code that ends any colorized span.
RESET = "\033[0m"


#Define supports_color, which decides whether we should actually emit
#escape codes or just print plain text.
def supports_color():
    #Respect the NO_COLOR convention (https://no-color.org/) above all else.
    if os.environ.get("NO_COLOR"):
        #The user explicitly asked for no color, anywhere.
        return False
    #If output is being redirected to a file or piped to another program,
    #raw escape codes would just clutter that file, so stay plain there.
    if not sys.stdout.isatty():
        #Not an interactive terminal, so skip color.
        return False
    #Otherwise, color is safe to use.
    return True


#Define colorize, the one function every other file calls to wrap text in
#a color. It silently does nothing if color is not appropriate right now.
def colorize(text, kind):
    #If color is not supported right now, return the text unchanged.
    if not supports_color():
        #Hand back the plain, uncolored text.
        return text
    #Look up the escape code for this kind, defaulting to no code at all.
    code = CODES.get(kind, "")
    #If we do not recognize this "kind", just return the plain text.
    if not code:
        #Hand back the plain text rather than guessing a color.
        return text
    #Wrap the text in the color code and the reset code.
    return f"{code}{text}{RESET}"
