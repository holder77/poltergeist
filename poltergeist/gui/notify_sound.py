#DESCRIPTION: This file plays the short "ding" chime the GUI uses when a
#             brand-new CRITICAL (high-severity) finding shows up on the
#             live Dashboard - the sound half of the same notification
#             feature app.py's icon-flashing is the visual half of. The
#             actual waveform is SYNTHESIZED right here, in plain Python,
#             the moment it's first needed - not loaded from a bundled
#             .wav file - for the exact same reason gui/icon.py's own
#             module docstring gives for drawing the ghost from geometry
#             instead of shipping an image: this project ships as plain
#             source with no build step, and a bundled binary asset is
#             one more thing that can go missing or get mangled when the
#             whole project is zipped and copied somewhere else. A
#             two-tone bell (a C6 fundamental plus a G6 layered on top,
#             both fading with a short exponential decay) built from
#               nothing but Python's own math.sin() and the stdlib 'wave'
#             module - no numpy, no audio library, nothing this project
#             didn't already need. ~40,000 samples computed in a tight
#             loop is a few milliseconds of work even on a slow machine,
#             so there is no real cost to building it fresh each time
#             either, though _ding_wav_bytes() below caches it anyway
#             since the exact same bytes are correct for the life of the
#             running process.
#
#             PLAYBACK itself is platform-specific, same "prefer the
#             stdlib or a shelled-out command over a new pip dependency"
#             preference this project already follows elsewhere (see
#             ntp_sync.py's own top comment, and log_review.py's wevtutil/
#             journalctl calls): Windows has 'winsound' in the standard
#             library, which can play a WAV straight out of memory with
#             no temp file at all. Linux has no stdlib audio-playback
#             module, so this shells out to whichever of a few very
#             common command-line players is actually installed (paplay,
#             then aplay, then ffplay), trying each in turn and moving on
#             if one is missing - and if NONE of them are present, it
#             says so plainly and lets the caller fall back to Tk's own
#             built-in root.bell() (a plain system beep, not this exact
#             chime, but still an audible alert) rather than silently
#             doing nothing.

#import platform to decide which playback path to use.
import platform

#import wave/io/math/struct to synthesize and encode the chime itself.
import wave
import io
import math
import struct

#import subprocess/shutil/tempfile/os for the Linux shell-out path.
import subprocess
import shutil
import tempfile
import os

#Store whether we are on Windows once for the whole file to reuse.
IS_WINDOWS = platform.system() == "Windows"

SAMPLE_RATE = 44100
DURATION_SECONDS = 0.9

#Module-level cache: the synthesized chime's raw WAV bytes, built once on
#first use and reused for every later ding this same running process
#plays - see this file's own top comment for why rebuilding it every
#time would still be cheap, but there is no reason to even pay that
#small cost twice.
_cached_wav_bytes = None


#Define _synthesize_ding_wav_bytes, which builds the exact chime sampled
#and approved by the user before this was wired in: a C6 (1046.5 Hz)
#fundamental layered with a quieter G6 (1568.0 Hz) a fifth above it, both
#under one shared exponential-decay envelope so the whole thing fades
#out smoothly rather than cutting off abruptly, encoded as a standard
#mono 16-bit PCM WAV file (in memory - no file written to disk here).
def _synthesize_ding_wav_bytes():
    sample_count = int(SAMPLE_RATE * DURATION_SECONDS)
    #A short linear fade-in on the very first few samples only, so the
    #chime doesn't start with an audible click (a waveform jumping
    #straight from silence to full amplitude on sample 0 is what causes
    #that click).
    fade_in_samples = int(SAMPLE_RATE * 0.02)
    samples = []
    for i in range(sample_count):
        t = i / SAMPLE_RATE
        #The shared decay envelope - fades from 1.0 down toward 0 over
        #the chime's own duration.
        envelope = math.exp(-t * (3.5 / DURATION_SECONDS))
        if i < fade_in_samples:
            envelope *= i / fade_in_samples
        fundamental = math.sin(2 * math.pi * 1046.5 * t) * 0.6
        fifth = math.sin(2 * math.pi * 1568.0 * t) * 0.35
        mixed = (fundamental + fifth) * envelope
        samples.append(mixed)
    #Normalize so the loudest single sample lands just under full scale,
    #avoiding any clipping once the two tones are mixed together.
    peak = max(abs(s) for s in samples) or 1.0
    scale = 0.85 / peak
    pcm_samples = [int(max(-1.0, min(1.0, s * scale)) * 32767) for s in samples]
    #Pack every sample as a signed 16-bit little-endian integer, all at
    #once (far faster than writing one sample at a time through 'wave').
    pcm_bytes = struct.pack(f"<{len(pcm_samples)}h", *pcm_samples)
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as wav_file:
        wav_file.setnchannels(1)
        wav_file.setsampwidth(2)
        wav_file.setframerate(SAMPLE_RATE)
        wav_file.writeframes(pcm_bytes)
    return buffer.getvalue()


#Define _ding_wav_bytes, the cached accessor every playback path below
#actually calls - builds the chime once, on first use, and reuses the
#exact same bytes for the rest of this process's life.
def _ding_wav_bytes():
    global _cached_wav_bytes
    if _cached_wav_bytes is None:
        _cached_wav_bytes = _synthesize_ding_wav_bytes()
    return _cached_wav_bytes


#Define _play_windows, which plays the chime straight out of memory via
#the standard library's own 'winsound' module - no temp file needed at
#all on this OS. Returns True if playback was actually triggered.
def _play_windows():
    try:
        #winsound is Windows-only; importing it here (not at module level)
        #means this whole file still imports cleanly on Linux too.
        import winsound
        #SND_MEMORY plays WAV bytes already in memory rather than a path
        #on disk; SND_ASYNC returns immediately instead of blocking the
        #GUI's own event loop until the chime finishes playing.
        winsound.PlaySound(_ding_wav_bytes(), winsound.SND_MEMORY | winsound.SND_ASYNC)
        return True
    #Catch anything at all - a missing audio device, a locked-down
    #environment, whatever - rather than letting a notification sound
    #ever crash the GUI it's trying to alert someone about.
    except Exception:
        return False


#Define _play_linux, which shells out to whichever of a few very common
#command-line audio players is actually installed, in order, moving on
#to the next if one is missing - the exact same "try several well-known
#options, fall back cleanly" shape ntp_sync.py's own NTP_SERVERS list
#uses. Writes the chime to ONE fixed, reused temp file (overwritten each
#time, not a fresh file per ding) so repeated notifications never leave
#a pile of stray files behind in the system temp directory. Returns True
#if a player was actually found and launched.
def _play_linux():
    #Write (or overwrite) the one shared temp file this function always
    #uses - cheap enough to do on every call that there is no real
    #benefit to trying to skip it when the file might already be there
    #from a previous ding.
    wav_path = os.path.join(tempfile.gettempdir(), "poltergeist_critical_ding.wav")
    try:
        with open(wav_path, "wb") as wav_file:
            wav_file.write(_ding_wav_bytes())
    #If we can't even write the temp file, there's nothing further to try.
    except Exception:
        return False
    #Try each player in turn - paplay (PulseAudio, the most common on a
    #modern desktop Linux) first, then aplay (plain ALSA, works even
    #without PulseAudio running), then ffplay (ffmpeg's own player, a
    #common fallback when neither of the above is installed).
    for player, args in (
        ("paplay", [wav_path]),
        ("aplay", ["-q", wav_path]),
        ("ffplay", ["-nodisp", "-autoexit", "-loglevel", "quiet", wav_path]),
    ):
        #shutil.which() checks PATH without actually running anything -
        #cheaper and clearer than launching and catching FileNotFoundError.
        if shutil.which(player) is None:
            continue
        try:
            #Fire-and-forget: never block the GUI's own event loop
            #waiting for a sound to finish playing. Output is discarded
            #rather than left to inherit this process's own stdout/stderr.
            subprocess.Popen([player] + args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        #A player that's on PATH but fails to actually launch for some
        #other reason - try the next one instead of giving up entirely.
        except Exception:
            continue
    #Nothing on this box could play it.
    return False


#Define play_critical_ding, the one function app.py actually calls.
#Returns True if a real playback attempt was made (not a guarantee sound
#was actually HEARD - a Bluetooth speaker that's off, for instance, is
#invisible to this check), False if nothing on this box could even be
#tried, in which case the caller is expected to fall back to Tk's own
#root.bell() instead of the person getting no alert at all.
def play_critical_ding():
    if IS_WINDOWS:
        return _play_windows()
    return _play_linux()
