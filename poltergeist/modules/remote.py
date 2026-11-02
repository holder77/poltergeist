#DESCRIPTION: This module is how Poltergeist reaches the ONE remote
#             machine a "remote" target points at (see config.py's
#             "target" key). The model is "deploy & run remotely": copy
#             this whole Poltergeist install over once, give it its OWN
#             small config describing itself, and then for every action
#             just ask it to run the equivalent flag on ITSELF and copy
#             its findings back. That means every check module in this
#             project stays completely unaware that a remote target even
#             exists - as far as persistence.py, network.py, and everyone
#             else are concerned, they are always running "locally",
#             because on the far end of the SSH connection, they are.
#
#             This file talks to that remote machine using paramiko, a
#             pure-Python SSH library, instead of shelling out to the
#             system's own ssh/scp/rsync programs the way an earlier
#             version of this idea ("Fleet") did. Three things changed
#             that decision: Windows does not always have an SSH client
#             installed at all, scp and ssh disagree about whether a
#             custom port is "-P" or "-p" (a classic, easy-to-get-wrong
#             gotcha), and - the real reason - some competition/practice
#             machines (the prompt's own example: a challenge VM reachable
#             only with a password) have no key-based login configured at
#             all. paramiko can do key-based OR password-based login with
#             one consistent API on both Windows and Linux, so this file
#             supports all three ways in a person might actually have:
#               - "agent_or_default": let a running SSH agent or the
#                 normal ~/.ssh key files handle it, same as typing a bare
#                 "ssh user@host" yourself.
#               - "key_file": a specific private key file, picked in the
#                 wizard (optionally passphrase-protected).
#               - "password": a plain username + password.
#             Whichever secret a connection actually needs (a password or
#             a key's passphrase) is passed into every function below as
#             a small in-memory dictionary, never saved into config.json,
#             never logged, and never written to disk anywhere by this
#             file. The wizard that collects it is responsible for asking
#             again every time Poltergeist starts, the same way it
#             re-confirms everything else about the target on every launch.

#import os so we can walk the local repo during deploy and build evidence
#file paths the same way the rest of this project does.
import os

#import json so remote config/discovery payloads can be built and parsed.
import json

#import socket so we can recognize network-level errors (timeouts,
#refused connections) and explain them in plain English instead of
#dumping a raw exception at the user.
import socket

#import shlex so any value we splice into a remote shell command string
#(a folder path, a Shield rule, a label) is quoted safely - this is the
#one place in this file a string we did not fully control ends up inside
#a command line, so this is the one place that quoting really matters.
import shlex

#import paramiko itself: SSHClient for the connection, and its specific
#exception classes so we can tell an auth failure apart from a network
#problem apart from "that key needs a passphrase" and say something useful
#about each one instead of one generic "something went wrong". This is
#wrapped in a try/except on purpose: paramiko is only needed the moment
#someone actually sets up a REMOTE target, and every local-only feature
#(which is most of this program, for most people, most of the time)
#should keep working perfectly even on a machine where `pip install -r
#requirements.txt` has not been run yet. make_client() below is the one
#place this is actually checked, since every other function in this file
#reaches paramiko only by calling that one first.
try:
    #The normal case: paramiko is installed.
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    #Not installed. Leave a plain None in its place so a stray reference
    #fails loudly and obviously rather than on some confusing tangent.
    paramiko = None
    PARAMIKO_AVAILABLE = False


#Define known_hosts_path, a tiny helper so every function below agrees on
#where this ONE target's trusted host keys are remembered. This is
#deliberately a Poltergeist-managed file inside evidence_dir, not the
#analyst's real ~/.ssh/known_hosts - keeping it self-contained means nothing
#here can clash with or depend on whatever else lives in that person's own
#SSH setup, the same "keeps its own small state file" pattern tripwire.py
#and logging_health.py already use.
def known_hosts_path(config):
    #Build the path inside the evidence directory.
    return os.path.join(config["evidence_dir"], "poltergeist_known_hosts")


#Define make_client, which builds a paramiko SSHClient with the right
#host-key policy already wired up: trust a host we have never seen before
#(convenient for a competition's freshly-built boxes, same trade-off the
#original SSH_OPTIONS made with StrictHostKeyChecking=accept-new), but if
#a host we HAVE seen before suddenly presents a DIFFERENT key, paramiko
#raises before ever asking the policy what to do - so this still catches
#the "someone swapped what's on the other end of this connection" case.
def make_client(config):
    #This is the one chokepoint every other function in this file reaches
    #paramiko through (directly or via connect() below), so this is the
    #one place that needs to check it is actually installed.
    if not PARAMIKO_AVAILABLE:
        #Raise a plain, clear RuntimeError - not a paramiko-specific
        #exception type, since paramiko itself is exactly what is
        #missing - with the exact fix spelled out.
        raise RuntimeError("paramiko is not installed - run: pip install -r requirements.txt (or: pip install paramiko)")
    #Build a plain SSHClient with no host keys loaded yet.
    client = paramiko.SSHClient()
    #If we have talked to a target before, load what we remembered about it.
    saved_path = known_hosts_path(config)
    if os.path.exists(saved_path):
        #Wrap in a try block since a hand-edited or corrupted file should
        #never be the reason a connection attempt crashes outright.
        try:
            #Load the previously-seen host keys from our own small file.
            client.load_host_keys(saved_path)
        #If the file cannot be read for any reason, just start fresh.
        except Exception:
            #Deliberately do nothing; connecting still works either way.
            pass
    #AutoAddPolicy only ever runs for a host paramiko does NOT already
    #have an entry for - a key mismatch for an already-known host is
    #rejected before this policy is even consulted, which is exactly the
    #"accept new, reject changed" behavior this tool wants.
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    #Hand back the ready-to-connect client.
    return client


#Define describe_connect_error, which turns the handful of exceptions a
#failed connection attempt can raise into one plain-English sentence,
#instead of showing a raw Python exception to someone mid-competition.
def describe_connect_error(exc):
    #If paramiko itself is not installed, make_client() already raised a
    #plain RuntimeError with the exact fix spelled out - every isinstance
    #check below assumes paramiko's own exception classes actually exist,
    #which they do not in that case, so just hand that message straight
    #through instead of risking a second, more confusing crash on top of it.
    if not PARAMIKO_AVAILABLE:
        #str(exc) is already the clear "paramiko is not installed..." text.
        return str(exc)
    #A wrong password, wrong key, or wrong username all surface as this.
    if isinstance(exc, paramiko.AuthenticationException):
        #Name the most likely fixes without guessing which one applies.
        return "authentication failed - check the username, and the password/key/passphrase"
    #A specific, very common case: the key file is real, but needs a
    #passphrase we did not supply.
    if isinstance(exc, paramiko.ssh_exception.PasswordRequiredException):
        #Tell the user exactly what is missing.
        return "that key file is passphrase-protected - enter its passphrase and try again"
    #We were given a key file path that does not actually exist.
    if isinstance(exc, FileNotFoundError):
        #Name the missing path if we have one.
        return f"key file not found: {getattr(exc, 'filename', '') or ''}".strip()
    #The connection attempt took too long to even complete.
    if isinstance(exc, socket.timeout):
        #Suggest the most common causes of a hung connection attempt.
        return "connection timed out - check the host/port and that the machine is reachable"
    #Nothing was listening on that host/port at all.
    if isinstance(exc, ConnectionRefusedError):
        #Ask the question that usually explains this.
        return "connection refused - is an SSH server actually running on that host/port?"
    #Any other network-level problem (DNS failure, unreachable network).
    if isinstance(exc, OSError):
        #Fall back to Python's own description of the OS error.
        return f"network error: {exc}"
    #Anything else SSH-protocol-related that is not one of the above.
    if isinstance(exc, paramiko.SSHException):
        #Fall back to paramiko's own message.
        return f"SSH error: {exc}"
    #A truly unexpected exception type - show whatever it says.
    return str(exc) or exc.__class__.__name__


#Define connect, the single function every other function in this file
#uses to actually open a connection, branching on target["auth_mode"] so
#the rest of this file never has to think about which of the three ways
#in is being used. secret is the small in-memory-only dict holding
#whatever password/passphrase this auth_mode actually needs; it may be
#None or {} for "agent_or_default", which needs no secret at all.
def connect(config, target, secret=None, timeout=10):
    #Default to an empty secret so .get() calls below never crash on None.
    secret = secret or {}
    #Build a fresh client with our host-key policy already configured.
    client = make_client(config)
    #Start the arguments every auth mode needs in common.
    connect_kwargs = {
        #.get() rather than [] on purpose: in normal use these are always
        #filled in (the wizard requires them, and config.py's loader backs
        #every saved target dict with its defaults), but if a hand-edited
        #config.json is missing one, this must fail with paramiko's own
        #clear authentication/protocol error - never a bare, confusing
        #KeyError that describe_connect_error() below has no good way to
        #translate into something a person can act on.
        "hostname": target.get("host", ""),
        "port": int(target.get("port") or 22),
        "username": target.get("user", ""),
        "timeout": timeout,
        "banner_timeout": timeout,
        "auth_timeout": timeout,
    }
    #Branch on which of the three auth modes this target is configured for.
    auth_mode = target.get("auth_mode", "agent_or_default")
    if auth_mode == "password":
        #Use exactly the typed password, and nothing else - do not also
        #let paramiko wander off and try an agent or default key files,
        #since that could succeed against a DIFFERENT identity than the
        #one the user actually meant to test here.
        connect_kwargs["password"] = secret.get("password", "")
        connect_kwargs["look_for_keys"] = False
        connect_kwargs["allow_agent"] = False
    elif auth_mode == "key_file":
        #Point paramiko at exactly the key file the wizard was given,
        #with its passphrase if one was supplied (None is fine - that is
        #exactly what an unprotected key needs).
        connect_kwargs["key_filename"] = target.get("key_path") or None
        connect_kwargs["passphrase"] = secret.get("passphrase") or None
        connect_kwargs["look_for_keys"] = False
        connect_kwargs["allow_agent"] = False
    else:
        #"agent_or_default": behave exactly like typing a bare
        #"ssh user@host" yourself - try a running agent, then the usual
        #~/.ssh/id_* files.
        connect_kwargs["look_for_keys"] = True
        connect_kwargs["allow_agent"] = True
    #Actually attempt the connection. Any failure here is left to the
    #caller to catch - every public function below wraps its own call to
    #connect() so it can add a label-prefixed, human-readable message.
    client.connect(**connect_kwargs)
    #The connection succeeded, which means this host's key is now either
    #freshly trusted or re-confirmed - make sure the folder we are about
    #to save it into actually exists, then remember it for next time.
    os.makedirs(config["evidence_dir"], exist_ok=True)
    try:
        #Persist whatever AutoAddPolicy just learned to our own file.
        client.save_host_keys(known_hosts_path(config))
    #Saving the known-hosts file failing is not worth failing the whole
    #connection over - at worst, the next connection re-trusts it the same
    #way this one just did.
    except Exception:
        #Deliberately do nothing and keep going.
        pass
    #Hand back the live, connected client.
    return client


#Define remote_join, since a remote target is scoped to Linux for now
#(see run_wizard()'s comments in cli.py for why), remote paths are always
#POSIX-style - "/" - regardless of what OS the analyst's own machine
#uses. os.path.join must never be used for a remote path, since on
#Windows it would silently produce a backslash the remote shell cannot
#use. Public (no leading underscore) since cli.py's wizard also needs it
#to build the remote evidence_dir path when pushing the final config.
def remote_join(*parts):
    #Join every non-empty, non-"." part with a single forward slash.
    return "/".join(piece.strip("/") for piece in parts if piece and piece != ".")


#Define _sftp_makedirs, a small "mkdir -p" for SFTP, since sftp.mkdir()
#only makes one level and fails if that level already exists.
def _sftp_makedirs(sftp, remote_dir):
    #Nothing to do for an empty/root path.
    if not remote_dir:
        #Return immediately; there is no directory to create.
        return
    #Walk the path one segment at a time, creating each as we go.
    built_so_far = ""
    for segment in remote_dir.strip("/").split("/"):
        #Extend the path we have built by one more segment.
        built_so_far = f"{built_so_far}/{segment}" if built_so_far else segment
        #Try to create this level; an IOError almost always just means it
        #already exists, which is the normal case on every deploy after
        #the first one.
        try:
            #Attempt to create this one directory level.
            sftp.mkdir(built_so_far)
        except IOError:
            #Already exists - nothing further to do for this level.
            pass


#The plain, fixed names every deploy must never copy up to the remote
#machine: version control/cache clutter, and this machine's own default
#(first-instance) evidence folder, config file, and cached host key.
_DEPLOY_EXCLUDED_NAMES = {".git", "__pycache__", ".pytest_cache", "evidence", "poltergeist_config.json", "poltergeist_known_hosts"}


#Define _is_excluded_from_deploy, which ALSO excludes every OTHER running
#instance's own numbered evidence folder/config file - "evidence_2",
#"poltergeist_config_3.json", and so on (see config.py's own
#_select_instance_paths() for where these numbered names come from: a
#second, third, etc. simultaneously running local instance, each with its
#own separate config/evidence/baseline so they never share state with
#each other). Without this, deploying to a remote target from whichever
#instance happens to NOT be the plain/unnumbered one would leak that
#instance's own local findings/settings onto the target too, exactly the
#thing _DEPLOY_EXCLUDED_NAMES above already exists to prevent for the
#plain names - this just extends the same protection to every slot, not
#only the first one.
def _is_excluded_from_deploy(name):
    #The fixed names are always excluded, regardless of instance.
    if name in _DEPLOY_EXCLUDED_NAMES:
        return True
    #A numbered evidence folder from a DIFFERENT local instance -
    #"evidence_2", "evidence_17", and so on. (This machine's OWN
    #config.evidence_dir, for whichever instance is doing the deploying
    #right now, is passed in as this config's own evidence_dir setting,
    #never relied on matching one of these generic names - but it is
    #also, correctly, never deployed either way, since the setup wizard
    #never points evidence_dir at a folder INSIDE the install itself.)
    if name.startswith("evidence_") and name[len("evidence_"):].isdigit():
        return True
    #A numbered config file from a different local instance -
    #"poltergeist_config_2.json", and so on.
    if name.startswith("poltergeist_config_") and name.endswith(".json") \
            and name[len("poltergeist_config_"):-len(".json")].isdigit():
        return True
    #Every per-instance lock file too (created next to each config file -
    #see config.py again) - never anything a remote target would need.
    if name.startswith("poltergeist_config") and name.endswith(".json.lock"):
        return True
    #Not one of the above - safe to deploy.
    return False


#Define deploy_to_target, which copies this entire Poltergeist install up
#to the target over SFTP (paramiko's file-transfer protocol, carried over
#the same SSH connection - no separate scp/rsync program needed). It walks
#the local repo itself rather than shelling out, which is also what makes
#excluding evidence/config totally reliable even when the system has no
#rsync installed to do that filtering for us.
#
#Returns (True, None) on success, or (False, a_plain_English_reason) on
#failure - NOT a bare bool. probe_target_remote() below needs that real
#reason, not just a yes/no, specifically so its own passphrase-needed
#retry can actually recognize a passphrase-needed failure: if this
#function only ever handed back True/False, every caller would be stuck
#re-deriving "what actually went wrong" from nothing, which is exactly
#the bug that let a passphrase-protected key fail here with a reason that
#clearly said so, only for that detail to then get thrown away and
#replaced with a generic "deploy failed" by the time either wizard (text
#or GUI) checked whether a retry was worth offering.
def deploy_to_target(config, target, secret, local_repo_path):
    #Work out the label used in every printed line, for a consistent feed.
    label = target.get("label") or target.get("host", "remote")
    #Tell the user a deploy is starting, since a full copy can take a moment.
    print(f"  [{label}] deploying...")
    #Try to connect; any failure here means nothing was copied at all.
    try:
        #Open the connection using whichever auth mode this target needs.
        client = connect(config, target, secret)
    except Exception as exc:
        #Explain plainly why the deploy never even started.
        reason = describe_connect_error(exc)
        print(f"  [{label}] could not connect: {reason}")
        #Hand back the real reason, not just a bare False.
        return False, f"could not connect: {reason}"
    #Everything else is wrapped so the connection is always closed, deploy
    #succeed or fail.
    try:
        #Open the SFTP (file transfer) channel on top of the connection.
        sftp = client.open_sftp()
        #Work out the remote folder this install is going into.
        remote_root = target.get("remote_path") or "poltergeist"
        #Make sure that folder exists before copying anything into it.
        _sftp_makedirs(sftp, remote_root)
        #Count how many files actually get copied, for the confirmation line.
        file_count = 0
        #Walk the local repo top-down, copying every file we do not exclude.
        for current_dir, subdirs, files in os.walk(local_repo_path):
            #Prune excluded folders IN PLACE so os.walk never even
            #descends into them - this is what keeps a huge .git history
            #or __pycache__ from slowing a deploy down at all.
            subdirs[:] = [d for d in subdirs if not _is_excluded_from_deploy(d)]
            #Work out this folder's path relative to the repo root.
            relative_dir = os.path.relpath(current_dir, local_repo_path)
            #Translate that into the matching remote folder path.
            remote_dir = remote_root if relative_dir == "." else remote_join(remote_root, relative_dir.replace(os.sep, "/"))
            #Make sure this folder exists on the remote end too.
            _sftp_makedirs(sftp, remote_dir)
            #Copy every file in this folder that is not on the exclude list.
            for filename in files:
                #Skip anything on the never-deploy list.
                if _is_excluded_from_deploy(filename):
                    #Move on to the next file without copying this one.
                    continue
                #Build the full local source path for this one file.
                local_file_path = os.path.join(current_dir, filename)
                #Build the matching remote destination path.
                remote_file_path = remote_join(remote_dir, filename)
                #Actually copy the file up over SFTP.
                sftp.put(local_file_path, remote_file_path)
                #Count it toward the confirmation message.
                file_count += 1
        #Close the SFTP channel; the SSH connection itself closes below.
        sftp.close()
    #Catch anything that went wrong partway through the copy.
    except Exception as exc:
        #Explain what failed, with whatever detail the exception gives us.
        reason = str(exc) or exc.__class__.__name__
        print(f"  [{label}] deploy FAILED: {reason}")
        #Hand back the real reason, not just a bare False.
        return False, f"deploy failed: {reason}"
    #Always close the connection, whether the deploy succeeded or not.
    finally:
        #Close the underlying SSH connection.
        client.close()
    #Confirm success and how much was actually copied.
    print(f"  [{label}] deploy OK ({file_count} files)")
    #Return (True, None) so the caller knows it is safe to proceed.
    return True, None


#Define push_remote_config, which writes a tailored poltergeist_config.json
#straight into the target's deployed folder over SFTP - no local temp file
#needed, since sftp.open() can write directly to a remote path.
#
#Returns (True, None) on success, or (False, a_plain_English_reason) on
#failure - the same (success, reason) shape deploy_to_target() uses just
#above, and for the same reason: probe_target_remote() needs the real
#explanation to show the person, not a generic placeholder.
def push_remote_config(config, target, secret, remote_config_dict):
    #Work out the label used in the error message, if any.
    label = target.get("label") or target.get("host", "remote")
    #Try to connect first; nothing else can happen without a connection.
    try:
        #Open the connection.
        client = connect(config, target, secret)
    except Exception as exc:
        #Explain why nothing was written.
        reason = describe_connect_error(exc)
        print(f"  [{label}] could not connect: {reason}")
        #Hand back the real reason, not just a bare False.
        return False, f"could not connect: {reason}"
    #Wrap the actual write so the connection always gets closed afterward.
    try:
        #Open the SFTP channel.
        sftp = client.open_sftp()
        #Work out the remote folder this config is going into.
        remote_root = target.get("remote_path") or "poltergeist"
        #Build the full remote path to poltergeist_config.json itself.
        remote_config_path = remote_join(remote_root, "poltergeist_config.json")
        #Open that remote path for writing and write the JSON straight into it.
        with sftp.open(remote_config_path, "w") as remote_file:
            #Write nicely indented JSON, same as config.py's save_config does
            #locally, so a teammate who looks at it later can still read it.
            remote_file.write(json.dumps(remote_config_dict, indent=2))
        #Close the SFTP channel.
        sftp.close()
    #Catch anything that went wrong while writing.
    except Exception as exc:
        #Explain what failed.
        reason = str(exc) or exc.__class__.__name__
        print(f"  [{label}] could not write the remote config: {reason}")
        #Hand back the real reason, not just a bare False.
        return False, f"could not write the remote config: {reason}"
    #Always close the connection either way.
    finally:
        #Close the underlying SSH connection.
        client.close()
    #Everything succeeded.
    return True, None


#Define run_remote_command, which runs ONE command on the target and
#streams its output back live, line by line, prefixed with the target's
#label - this is what every ordinary action (scan, baseline, Shield rule,
#and so on) actually calls.
#
#stdin_text works exactly the same way it does on run_remote_command_capture
#below (same reasoning, same "send it, then signal EOF" approach) - it
#exists here so dispatch() can elevate the ACTUAL scan/action commands
#with "sudo -S", not just the one-off psutil installer.
#
#existing_client is optional: when the caller already has an open, live
#connection (see dispatch() below, which opens ONE connection and reuses
#it for both the command AND the evidence pull afterward), pass it here
#to run this command over it instead of opening (and later closing) a
#brand new one. This exists specifically because a competition box's own
#SSH server commonly rate-limits or throttles how many NEW connections
#one source IP can open in a short window (exactly the kind of defense
#this tool's own users are taught to set up) - and the OLD code opened
#TWO fresh connections per scan (one here, one in pull_evidence()), every
#single ambient scan cycle (every 15s by default). That is 8 new logins
#a minute against the same box, easily enough to look like a connection
#flood even though every single one used the right password - which is
#exactly what caused the "it just freezes, authentication failed, over
#and over" bug: the SECOND of the two connections kept getting refused by
#the target's own defenses, not because the credentials were ever wrong.
#Reusing one connection for the whole dispatch() call halves that rate.
#When existing_client is given, this function does NOT close it - the
#caller that opened it owns closing it, exactly like a borrowed resource.
def run_remote_command(config, target, secret, remote_command, label=None, stdin_text=None, existing_client=None):
    #Work out the label used on every printed line.
    label = label or target.get("label") or target.get("host", "remote")
    #Borrow the caller's already-open connection if given; otherwise open
    #(and, at the end, close) our own, exactly like before this change.
    owns_client = existing_client is None
    if existing_client is not None:
        #Use the connection handed to us - already proven to work.
        client = existing_client
    else:
        #Try to connect; nothing can run without a connection.
        try:
            #Open the connection.
            client = connect(config, target, secret)
        except Exception as exc:
            #Explain why the command never ran at all.
            print(f"  [{label}] could not connect: {describe_connect_error(exc)}")
            #Return False so the caller knows nothing happened.
            return False
    #Wrap the actual run so an owned connection is always closed
    #afterward - a BORROWED one (existing_client was given) is left
    #alone; the caller that opened it is responsible for closing it.
    try:
        #Open a plain command-execution channel on this connection.
        channel = client.get_transport().open_session()
        #Combine stderr into the same stream as stdout AT THE CHANNEL
        #LEVEL - deliberately NOT by allocating a pty. A pty would make
        #the remote process think it is talking to a real terminal, and
        #this project's own color.py checks exactly that (isatty()) to
        #decide whether to emit ANSI color codes - codes a Tkinter Text
        #widget cannot render, the same class of bug the isatty() fix
        #dealt with locally. Without a pty, the remote side correctly
        #sees a non-terminal and stays plain text, same as if its own
        #output were piped to a file.
        channel.set_combine_stderr(True)
        #Actually start the remote command running.
        channel.exec_command(remote_command)
        #If this command needs something fed to its stdin (right now: only
        #a sudo password, same as the capture version below), send it now
        #and signal EOF - see run_remote_command_capture's own comment for
        #why this matters for a command like "sudo -S" that reads exactly
        #one line and stops.
        if stdin_text is not None:
            channel.send(stdin_text.encode("utf-8") if isinstance(stdin_text, str) else stdin_text)
            try:
                channel.shutdown_write()
            except Exception:
                #Deliberately do nothing; most commands do not care.
                pass
        #Wrap the channel as a line-reading file object.
        output_stream = channel.makefile("r")
        #Print each line as it arrives, live, with the label in front.
        for line in output_stream:
            #Strip the trailing newline ourselves since print() adds one.
            print(f"  [{label}] {line.rstrip()}")
        #Wait for the remote command to actually finish and read its exit code.
        exit_status = channel.recv_exit_status()
    #Close the connection, command succeed or fail - but ONLY if we are
    #the one who opened it; a borrowed existing_client is the caller's to
    #close, not ours (see this function's own docstring above).
    finally:
        if owns_client:
            #Close the underlying SSH connection.
            client.close()
    #A non-zero exit code means the remote command itself failed.
    if exit_status != 0:
        #Say so plainly, including the code for anyone who wants to look it up.
        print(f"  [{label}] remote command exited with code {exit_status}")
        #Return False so the caller knows this action did not succeed.
        return False
    #The remote command ran and exited cleanly.
    return True


#Define run_remote_command_capture, the non-streaming twin of the function
#above: it waits for the command to finish and hands back its FULL output
#as one string, instead of printing it line by line. Used only where we
#need to actually read/parse the result ourselves (remote discovery JSON,
#the connection test), not just show it to a human.
#
#stdin_text is optional, and exists for exactly one case right now:
#check_remote_dependencies()'s own LAST-RESORT fallback needs to answer
#"sudo -S" with the same SSH password the person already typed in, the
#same way the Shadow Watch/Harbinger tool this was compared against does
#it for its own `sudo -S -p '' id -un` root check. When given, it's sent
#to the remote command's stdin right after starting it, then stdin is
#shut down (signals EOF) so a command like "sudo -S" that reads exactly
#one line and stops never hangs waiting for a second line that is never
#coming.
def run_remote_command_capture(config, target, secret, remote_command, timeout=30, stdin_text=None):
    #Open the connection; let the caller handle a connection failure.
    client = connect(config, target, secret)
    #Wrap the run so the connection is always closed afterward.
    try:
        #Open a command-execution channel, same as the streaming version.
        channel = client.get_transport().open_session()
        #Combine stderr into stdout, same reasoning as above.
        channel.set_combine_stderr(True)
        #Give the whole command this long to finish before giving up.
        channel.settimeout(timeout)
        #Start the remote command.
        channel.exec_command(remote_command)
        #If this command needs something fed to its stdin (right now:
        #only a sudo password), send it now, then signal EOF so whatever
        #is reading stdin on the other end knows nothing more is coming.
        if stdin_text is not None:
            #Encode to bytes the same tolerant way every other write in
            #this file does.
            channel.send(stdin_text.encode("utf-8") if isinstance(stdin_text, str) else stdin_text)
            #Not every paramiko version's Channel exposes this the same
            #way, and a command that does not even read stdin should
            #never be the reason this whole call fails - best-effort only.
            try:
                #Shut down the write side - this is what actually sends EOF.
                channel.shutdown_write()
            except Exception:
                #Deliberately do nothing; most commands do not care.
                pass
        #Collect every chunk of output as it arrives.
        collected_chunks = []
        while True:
            #Try to read the next chunk; a timeout here means the remote
            #command is taking too long and we give up on waiting for more.
            try:
                #Read up to 4KB at a time.
                chunk = channel.recv(4096)
            except socket.timeout:
                #Stop waiting; return whatever we collected so far.
                break
            #An empty chunk means the remote side closed the stream - done.
            if not chunk:
                #Stop reading; there is nothing more coming.
                break
            #Decode and keep this chunk, tolerating any odd bytes rather
            #than crashing on them.
            collected_chunks.append(chunk.decode("utf-8", errors="replace"))
        #Read the exit code the remote command actually finished with.
        exit_status = channel.recv_exit_status()
    #Always close the connection either way.
    finally:
        #Close the underlying SSH connection.
        client.close()
    #Join every collected chunk into the final output string.
    full_output = "".join(collected_chunks)
    #Hand back both whether it succeeded and everything it printed.
    return (exit_status == 0), full_output


#Define test_connection, used by the wizard's "Test Connection" step. It
#runs the simplest possible remote command and checks for the exact text
#we expect back, which exercises the FULL path (auth, a real command,
#reading the result) with no side effects on the target at all.
def test_connection(config, target, secret):
    #Try the round trip; any exception here means we could not even connect.
    try:
        #Ask the target to echo back one fixed, recognizable string.
        success, output = run_remote_command_capture(config, target, secret, "echo poltergeist_ok", timeout=10)
    except Exception as exc:
        #Hand back a clear explanation instead of a raw exception.
        return False, describe_connect_error(exc)
    #Confirm we got back exactly what we expect, not just "something".
    if success and "poltergeist_ok" in output:
        #Connection and command execution both genuinely work.
        return True, ""
    #Something ran but did not behave as expected - show what it said.
    return False, (output.strip()[:300] or "the command did not return the expected response")


#Define pull_evidence, which copies the target's findings.jsonl and (if it
#exists yet) baseline.json back down into THIS machine's own evidence_dir,
#so the local Dashboard, Scribe, and findings table always have a single,
#up-to-date local copy to read - no live connection needed just to look at
#what has already been found.
#
#existing_client is optional - see run_remote_command()'s own long
#comment on the same parameter for the full reasoning. dispatch() below
#passes its own already-open connection here instead of letting this
#function open a SECOND brand new one, which is what used to cause a
#genuine, repeating "authentication failed" against a box that had just
#authenticated fine moments earlier for the command itself - a box
#throttling how many new connections one source IP can open per minute
#doesn't care that the password was right both times.
def pull_evidence(config, target, secret, existing_client=None):
    #Work out the label used in any error message.
    label = target.get("label") or target.get("host", "remote")
    #Borrow the caller's connection if given; otherwise open (and, at the
    #end, close) our own - identical pattern to run_remote_command() above.
    owns_client = existing_client is None
    if existing_client is not None:
        #Use the connection handed to us - already proven to work.
        client = existing_client
    else:
        #Try to connect; nothing can be pulled without a connection.
        try:
            #Open the connection.
            client = connect(config, target, secret)
        except Exception as exc:
            #Explain why nothing could be pulled back.
            print(f"  [{label}] could not connect to pull evidence back: {describe_connect_error(exc)}")
            #Return False so the caller knows the pull did not happen.
            return False
    #Work out the remote folder this target was deployed to.
    remote_root = target.get("remote_path") or "poltergeist"
    #Make sure our own local evidence folder exists before writing into it.
    local_evidence_dir = config["evidence_dir"]
    os.makedirs(local_evidence_dir, exist_ok=True)
    #Track whether we actually pulled anything back at all.
    pulled_anything = False
    #Wrap the actual transfer so the connection always gets closed.
    try:
        #Open the SFTP channel.
        sftp = client.open_sftp()
        #Pull each file we care about, one at a time. "tripwire_state.json"
        #is what lets the LOCAL Dashboard and GUI's own "stop watching a
        #folder" picker show a remote target's currently-watched Tripwire
        #folders at all - without this, tripwire_add/tripwire_remove would
        #still work fine (they run entirely on the remote side), but the
        #analyst's own machine would have no way to know what's currently
        #being watched there. "canary_state.json" is the exact same story
        #for Canary's own seeded bait-folder list (canary_add/canary_remove).
        #"snapshot_state.json" is the same idea again for Medium's own
        #snapshot details (which volume/logical-volume/shadow-copy was
        #actually captured) - without this, the analyst's own machine
        #would have no way to tell whether a remote target even HAS a
        #usable snapshot to revert to, or what it covers.
        for filename in ("findings.jsonl", "baseline.json", "tripwire_state.json", "canary_state.json", "snapshot_state.json"):
            #Build the remote source path for this one file.
            remote_file_path = remote_join(remote_root, "evidence", filename)
            #Build the matching local destination path.
            local_file_path = os.path.join(local_evidence_dir, filename)
            #Try to pull it; a missing file (baseline.json before the
            #first remote baseline, say) is completely normal, not a failure.
            try:
                #Actually copy the remote file down.
                sftp.get(remote_file_path, local_file_path)
                #Remember that at least one file came back successfully.
                pulled_anything = True
            except IOError:
                #That file simply does not exist yet on the remote side.
                pass
        #Close the SFTP channel.
        sftp.close()
    #Catch anything else that went wrong during the pull.
    except Exception as exc:
        #Explain what failed.
        print(f"  [{label}] could not pull evidence back: {exc}")
        #Return False so the caller knows the pull did not fully succeed.
        return False
    #Close the connection either way - but ONLY if we are the one who
    #opened it; a borrowed existing_client belongs to the caller, same
    #rule as run_remote_command() above.
    finally:
        if owns_client:
            #Close the underlying SSH connection.
            client.close()
    #Hand back whether anything was actually pulled, for anyone who wants
    #to know ("baseline.json not back yet" vs "a real problem").
    return pulled_anything


#Define probe_target_remote, the single function the wizard calls to set
#up a brand-new (or re-confirmed) remote target in one go: deploy this
#install, hand the target a minimal config describing ONLY itself, then
#ask it to run its own discovery and hand that back - exactly the same
#discover() dictionary a LOCAL wizard page already knows how to read, so
#every page after this one in the wizard works identically either way.
def probe_target_remote(config, target, secret, local_repo_path):
    #Deploy first; nothing else here means anything if this fails. Note
    #this unpacks the REAL reason rather than reducing it to a bare bool -
    #the retry logic just below (and both wizards') depends on seeing an
    #actual message like "...passphrase required..." to recognize that
    #one specific, recoverable case, not a generic placeholder.
    deployed, deploy_error = deploy_to_target(config, target, secret, local_repo_path)
    if not deployed:
        #Hand back the real reason the caller can show directly.
        return None, deploy_error
    #Work out the remote folder we just deployed into.
    remote_root = target.get("remote_path") or "poltergeist"
    #Build the smallest config the remote side needs to run on ITSELF: its
    #own evidence folder (inside the same deployed folder) and a plain
    #"local" target, since from the remote machine's own point of view, it
    #IS the local machine - this is the whole "deploy & run remotely" idea.
    #evidence_dir is deliberately the BARE string "evidence", not
    #remote_join(remote_root, "evidence"). Every remote command this file
    #ever runs (see run_remote_command()'s callers below, and the
    #--discover-json command built just below this) starts with
    #"cd {remote_root} && ..." - so by the time this config is actually
    #read, the remote process's own current working directory IS
    #remote_root already. Prefixing evidence_dir with remote_root AGAIN
    #here used to double it up (e.g. remote_root "poltergeist" produced
    #the config value "poltergeist/evidence"), which - being a RELATIVE
    #path, resolved against a cwd that is already remote_root - pointed
    #one directory too deep (.../poltergeist/poltergeist/evidence instead
    #of .../poltergeist/evidence). pull_evidence() below always looks in
    #the correct, un-doubled location, so with the old bug every scan
    #genuinely found real findings (visible live in the streamed SSH
    #output) and wrote them somewhere real - just not anywhere
    #pull_evidence() would ever look, so the local Dashboard and findings
    #table stayed silent no matter how much the box actually had on it.
    minimal_remote_config = {
        "evidence_dir": "evidence",
        "target": {"mode": "local"},
    }
    #Push that config up before asking the remote side to do anything.
    pushed, push_error = push_remote_config(config, target, secret, minimal_remote_config)
    if not pushed:
        #Hand back the real reason.
        return None, push_error
    #Check that the remote machine's own python3 actually has psutil
    #before asking it to run anything real - see check_remote_dependencies()'s
    #own docstring for why this needs to be its own, clearly-labeled step
    #rather than letting a missing dependency masquerade as a generic
    #"remote discovery failed" a few lines down.
    dependency_error = check_remote_dependencies(config, target, secret)
    if dependency_error:
        #Hand back the specific, actionable reason.
        return None, dependency_error
    #Work out the label used for the message just below.
    label = target.get("label") or target.get("host", "remote")
    #Find out NOW, at Setup time, whether every real scan afterward is
    #going to be able to elevate with sudo - rather than letting the
    #person discover it later as a Dashboard full of "(nothing to
    #report)" sections with no explanation. This never blocks Setup from
    #succeeding either way; it is purely informational.
    elevation_works, elevation_detail = _test_remote_elevation(config, target, secret)
    if elevation_works:
        print(f"  [{label}] sudo elevation confirmed - scans will run as root, same as a locally-run scan with sudo/Administrator.")
    else:
        print(f"  [{label}] NOTE - scans on this target will run WITHOUT root: {elevation_detail}")
    #Build the remote command: change into the deployed folder, then ask
    #this same codebase to probe and print its OWN discovery data as JSON.
    remote_command = f"{_PYTHON3_RESOLVE}; cd {shlex.quote(remote_root)} && \"$PY3\" poltergeist.py --discover-json"
    #Run it and capture the result; let a connection failure bubble up
    #as a clear message rather than a raw exception.
    try:
        #Capture (not stream) this one, since we need to parse the result.
        success, output = run_remote_command_capture(config, target, secret, remote_command, timeout=20)
    except Exception as exc:
        #Hand back a clear explanation.
        return None, describe_connect_error(exc)
    #A non-zero exit code means discovery itself failed on the remote end.
    if not success:
        #Show whatever the remote side printed, trimmed to a reasonable length.
        return None, f"remote discovery failed: {output.strip()[:300]}"
    #Try to parse the JSON we got back.
    try:
        #Parse the captured text as JSON.
        discovered = json.loads(output)
    #If the output was not valid JSON (an unexpected remote error, say).
    except Exception:
        #Hand back the raw output so the user can see what actually happened.
        return None, f"could not parse the remote machine's discovery output: {output.strip()[:300]}"
    #Hand back the parsed discovery dictionary and no error.
    return discovered, None


#Define list_remote_directory, read_remote_log_list, and read_remote_log
#below: three small siblings of probe_target_remote() above, built on the
#exact same "ask the SAME deployed codebase to print its own answer as
#JSON, over a captured (not streamed) command" pattern - the one real
#difference is these three are called REPEATEDLY, interactively, as the
#person clicks through a folder tree or opens one log after another, so
#unlike probe_target_remote() (a one-time Setup step) they deliberately
#skip deploy_to_target()/push_remote_config()/check_remote_dependencies()
#every single call - the remote side was already deployed and configured
#once, back at Setup, and redoing all of that on every single folder
#click would make browsing feel sluggish for no real benefit. If the
#remote side was somehow never deployed at all, run_remote_command_
#capture() below still fails cleanly with a clear connection/command
#error instead of silently doing nothing.
def list_remote_directory(config, target, secret, path=""):
    #Work out the remote folder this target was deployed to.
    remote_root = target.get("remote_path") or "poltergeist"
    quoted_root = shlex.quote(remote_root)
    #Build the remote command: change into the deployed folder, then ask
    #this same codebase to list ONE folder (its own default/home/drive-
    #list when path is empty) and print the result as JSON.
    remote_command = f"{_PYTHON3_RESOLVE}; cd {quoted_root} && \"$PY3\" poltergeist.py --list-dir {shlex.quote(path)}"
    try:
        #Capture (not stream) this one, since we need to parse the result.
        success, output = run_remote_command_capture(config, target, secret, remote_command, timeout=20)
    except Exception as exc:
        #Hand back a clear explanation.
        return None, describe_connect_error(exc)
    if not success:
        #Show whatever the remote side printed, trimmed to a reasonable length.
        return None, f"could not list that folder: {output.strip()[:300]}"
    try:
        #Parse the captured text as JSON.
        return json.loads(output), None
    #If the output was not valid JSON (an unexpected remote error, say).
    except Exception:
        #Hand back the raw output so the user can see what actually happened.
        return None, f"could not parse the remote machine's folder listing: {output.strip()[:300]}"


def list_remote_logs(config, target, secret):
    #Work out the remote folder this target was deployed to.
    remote_root = target.get("remote_path") or "poltergeist"
    quoted_root = shlex.quote(remote_root)
    #Build the remote command: ask this same codebase which logs/event
    #channels IT can see (always the monitored machine's own OS/layout,
    #never the analyst's own machine's).
    remote_command = f"{_PYTHON3_RESOLVE}; cd {quoted_root} && \"$PY3\" poltergeist.py --list-logs"
    try:
        success, output = run_remote_command_capture(config, target, secret, remote_command, timeout=20)
    except Exception as exc:
        return None, describe_connect_error(exc)
    if not success:
        return None, f"could not list logs: {output.strip()[:300]}"
    try:
        return json.loads(output), None
    except Exception:
        return None, f"could not parse the remote machine's log list: {output.strip()[:300]}"


def read_remote_log(config, target, secret, name):
    #Work out the remote folder this target was deployed to.
    remote_root = target.get("remote_path") or "poltergeist"
    quoted_root = shlex.quote(remote_root)
    #Build the remote command: ask this same codebase to read and
    #analyze ONE specific log/channel (by the id read_remote_logs() just
    #handed back) and print the result as JSON. A longer timeout than the
    #two above - reading/analyzing a real log's full tail can take a
    #little longer than a quick directory or channel listing.
    remote_command = f"{_PYTHON3_RESOLVE}; cd {quoted_root} && \"$PY3\" poltergeist.py --read-log {shlex.quote(name)}"
    try:
        success, output = run_remote_command_capture(config, target, secret, remote_command, timeout=45)
    except Exception as exc:
        return None, describe_connect_error(exc)
    if not success:
        return None, f"could not read that log: {output.strip()[:300]}"
    try:
        return json.loads(output), None
    except Exception:
        return None, f"could not parse the remote machine's log content: {output.strip()[:300]}"


#A small, defensive shell fragment every remote command below is built on
#top of, instead of a bare "python3". paramiko's exec_command() (like
#every function in this file uses) runs a NON-interactive remote shell,
#which does NOT source .bashrc/.profile the way an interactive login
#shell does - so its PATH can be thinner than what the same user sees
#when they SSH in by hand and type commands one at a time. That gap is a
#real, documented gotcha (the same one the Harbinger/Shadow Watch tool
#this was compared against calls out explicitly: "find python3 by
#absolute path... later remote commands are python3 /full/path/...").
#"python3 not found" here does not necessarily mean the login itself is
#broken - a person can `ssh -p 2224 analyst@localhost` and get a working
#shell by hand while this exact kind of non-interactive command still
#fails to see where python3 lives. This resolves it defensively: use
#whatever "python3" already finds on PATH, and only fall back to the one
#near-universal absolute location if that lookup itself comes up empty.
_PYTHON3_RESOLVE = 'PY3="$(command -v python3 2>/dev/null || echo /usr/bin/python3)"'


#Define _PIP_INSTALL_PSUTIL_COMMAND, the shell fragment
#check_remote_dependencies() below runs FIRST when psutil turns out to be
#missing. First checks whether "$PY3" -m pip even WORKS at all - on a
#minimized distro image (an increasingly common competition-lab base:
#smaller to build, faster to boot, and this is exactly what one real
#practice VM this was tested against turned out to be) the pip MODULE
#itself can be stripped out entirely, which makes every "pip install"
#attempt fail immediately with "No module named pip" - not a sign
#psutil's install itself failed, but that there is no pip to run one
#with in the first place. When that happens, this tries `ensurepip`
#first (Python's own built-in way to bootstrap pip back in, where it is
#still present - it is sometimes stripped right along with pip on the
#same minimized image, which is why this is a "try it" and not a
#guarantee) before attempting the install. Once pip is confirmed usable
#one way or another, this chains FOUR install attempts with shell "||",
#each one only running if the one before it failed, so this single
#remote round trip covers every shape of "normal" Python environment we
#might land on: a personal venv-free install (--user is both allowed and
#the polite choice there), a modern distro that blocks any system-wide
#pip install outside a virtualenv under PEP 668 (needs
#--break-system-packages on top of --user), a root/admin shell where
#--user does not even apply, and that same PEP 668 restriction again
#without --user. Output from every attempt is appended to one temp log
#file so the caller can show whatever actually went wrong if all of this
#still fails, and that temp file is removed again right after - this
#should never leave stray files behind on someone else's machine.
_PIP_INSTALL_PSUTIL_COMMAND = (
    f'{_PYTHON3_RESOLVE}; '
    'LOG=/tmp/.poltergeist_pip_install.log; '
    '"$PY3" -m pip --version > "$LOG" 2>&1 '
    '|| "$PY3" -m ensurepip --user >> "$LOG" 2>&1 '
    '|| "$PY3" -m ensurepip >> "$LOG" 2>&1; '
    '"$PY3" -m pip install --user psutil >> "$LOG" 2>&1 '
    '|| "$PY3" -m pip install --user --break-system-packages psutil >> "$LOG" 2>&1 '
    '|| "$PY3" -m pip install psutil >> "$LOG" 2>&1 '
    '|| "$PY3" -m pip install --break-system-packages psutil >> "$LOG" 2>&1; '
    'cat "$LOG"; rm -f "$LOG"'
)


#Define _SUDO_PACKAGE_INSTALL_COMMAND, the LAST-RESORT fallback
#check_remote_dependencies() below reaches for only if the pip-based
#chain above STILL didn't make psutil importable - most commonly because
#pip itself could not be bootstrapped at all on a stripped-down image.
#Every mainstream Linux distro's own package manager carries psutil as a
#ready-built system package (no pip, no compiler, no internet-reachable
#PyPI needed - just the distro's own, usually-already-configured package
#mirror), so this tries the one this machine actually has: apt-get
#(Debian/Ubuntu), then dnf (Fedora/modern RHEL), then yum (older RHEL/
#CentOS) - in that order, each only attempted if the one before it isn't
#even present on PATH. This needs root, which needs a password - see
#check_remote_dependencies() for where that password comes from and why
#reusing it this way is safe. `sudo -S -p ''` is run exactly ONCE no
#matter which branch below actually runs, specifically so there is only
#ever one password prompt to answer over stdin, never two or three
#silently racing each other for the same single line of input.
_SUDO_PACKAGE_INSTALL_COMMAND = (
    "sudo -S -p '' sh -c '"
    "(command -v apt-get >/dev/null 2>&1 && apt-get update && apt-get install -y python3-psutil python3-pip) "
    "|| (command -v dnf >/dev/null 2>&1 && dnf install -y python3-psutil python3-pip) "
    "|| (command -v yum >/dev/null 2>&1 && yum install -y python3-psutil python3-pip) "
    "|| echo no-supported-package-manager-found"
    "' > /tmp/.poltergeist_sudo_install.log 2>&1; "
    "cat /tmp/.poltergeist_sudo_install.log; rm -f /tmp/.poltergeist_sudo_install.log"
)


#Define check_remote_dependencies, a cheap "can the remote machine's own
#python3 actually import psutil" probe - and, if not, an automatic
#attempt to fix that itself before ever bothering the person about it.
#Poltergeist's own check modules (persistence.py, processes.py,
#network.py, ...) need psutil INSTALLED ON THE REMOTE MACHINE too, not
#just on the analyst's own - deploy_to_target() only copies this
#project's own files, it never installs anything on its own. The whole
#point of connecting over SSH in the first place is that it already
#IS a shell on that machine, so rather than making a person open a
#second terminal and type the fix by hand, this reuses that exact same
#connection to run the fix itself, trying progressively more capable
#strategies: first plain `pip install` (several flag combinations - see
#_PIP_INSTALL_PSUTIL_COMMAND above), and - only if that still doesn't
#work, which usually means pip itself isn't even present on a minimized
#image - installing the distro's OWN pre-built psutil package as root via
#sudo (_SUDO_PACKAGE_INSTALL_COMMAND above), reusing the SAME password
#already typed into the wizard for this target's SSH login (exactly the
#same "ask once, reuse for sudo" approach the Shadow Watch/Harbinger tool
#this was compared against uses for its own root check) - never asked a
#second time, and never written anywhere. That reuse only happens for a
#"password" auth-mode target; a key-based login has no password to reuse,
#so that one fallback step is simply skipped for those, and the person is
#told which manual command to run instead. Only surfaces a message to the
#person at all once EVERY automatic attempt has genuinely been tried,
#with the real output from whichever attempts actually ran attached, so
#the real blocker (most often: no internet on an air-gapped competition
#box) is visible immediately rather than a second generic "psutil
#missing" with nothing new to act on. Called once, right after a
#successful deploy, specifically so a missing dependency gets its own
#clear, actionable path instead of being lumped in with a real connection
#failure a few lines later. Returns None once psutil is importable there
#(whether it already was, or this function just made it so), or a
#plain-English reason string if it still isn't after everything above.
def check_remote_dependencies(config, target, secret):
    label = target.get("label") or target.get("host", "remote")
    #Build the same defensively-resolved python3 command every other
    #remote command in this file uses, then just try to import psutil.
    check_command = f'{_PYTHON3_RESOLVE}; "$PY3" -c "import psutil" 2>&1'
    #Wrap the run itself, since a connection could still drop between the
    #deploy that just succeeded and this one extra round trip.
    try:
        #Capture (not stream) this one - it is a single pass/fail check.
        success, output = run_remote_command_capture(config, target, secret, check_command, timeout=15)
    except Exception as exc:
        #A connection-level failure here - describe it the normal way.
        return describe_connect_error(exc)
    #psutil is already importable there - nothing to do.
    if success:
        return None
    #Missing - try to fix it ourselves, over the same SSH connection we
    #already have, before asking the person to do anything by hand.
    print(f"  [{label}] psutil is missing on the remote machine's python3 - installing it there now...")
    try:
        #Give this one longer: an actual network install, not just a check.
        _install_success, install_output = run_remote_command_capture(
            config, target, secret, _PIP_INSTALL_PSUTIL_COMMAND, timeout=90)
    except Exception as exc:
        #The connection itself dropped mid-install - describe that plainly
        #rather than silently falling through to the generic message below.
        return (f"psutil is missing on the remote machine, and the automatic install attempt lost the "
                f"connection before it could finish: {describe_connect_error(exc)} - once it's reachable "
                "again, either run Setup again or install it there by hand: python3 -m pip install psutil")
    #Re-check with the EXACT same import command, regardless of what exit
    #code the chained install attempts themselves returned - pip's own
    #exit code is not a reliable signal here (the LAST attempt in the
    #chain is the one whose exit code shell "||" actually propagates, and
    #it may fail for an unrelated reason even once an EARLIER attempt in
    #the chain already succeeded) - whether the import itself now works
    #is the only thing that actually matters.
    try:
        recheck_success, _recheck_output = run_remote_command_capture(config, target, secret, check_command, timeout=15)
    except Exception as exc:
        return describe_connect_error(exc)
    if recheck_success:
        #Fixed it ourselves - say so, then let the caller carry straight on.
        print(f"  [{label}] psutil installed successfully on the remote machine.")
        return None
    #pip-based install still didn't work - usually because pip itself
    #could not be bootstrapped at all (a minimized image with no pip AND
    #no working ensurepip). If this target logs in with a plain password,
    #reuse that SAME password for one sudo prompt and try the distro's
    #own package manager instead - no pip required at all for this path.
    secret = secret or {}
    password = secret.get("password") if target.get("auth_mode") == "password" else None
    sudo_output = ""
    if password:
        print(f"  [{label}] pip-based install didn't work - trying the distro's own package manager via sudo...")
        try:
            #Reuse the SSH password as the sudo password, sent over
            #stdin - never passed as a command-line argument, and never
            #written to a log, a file, or anywhere else.
            _, sudo_output = run_remote_command_capture(
                config, target, secret, _SUDO_PACKAGE_INSTALL_COMMAND, timeout=120, stdin_text=password + "\n")
        except Exception as exc:
            #The connection dropped mid-install - note it, but still fall
            #through to the final re-check below rather than giving up
            #immediately, in case the install actually finished first.
            sudo_output = f"(lost the connection during the sudo install attempt: {describe_connect_error(exc)})"
        try:
            recheck_success2, _recheck_output2 = run_remote_command_capture(config, target, secret, check_command, timeout=15)
        except Exception as exc:
            return describe_connect_error(exc)
        if recheck_success2:
            #Fixed it ourselves, via the distro's own package manager this
            #time - say so, then let the caller carry straight on.
            print(f"  [{label}] psutil installed successfully on the remote machine (via sudo).")
            return None
    #Still missing after trying every install strategy above - now it
    #really does need a person to look at it, so hand back everything the
    #install attempts themselves actually said, not just "still missing."
    attempts_text = f"pip-based install said: {install_output.strip()[:300] or '(nothing printed)'}"
    if password:
        #Only mention the sudo attempt at all if it was actually tried -
        #a key-based login never reaches that step, so saying nothing
        #about it there would be misleading.
        attempts_text += f"\n\nsudo package-manager install said: {sudo_output.strip()[:300] or '(nothing printed)'}"
    return ("psutil is missing on the remote machine's own python3, and Poltergeist's automatic attempts "
            f"to install it there did not work. {attempts_text}\n\n"
            "This usually means the remote machine has no internet access (common on an isolated "
            "competition box) or an unusually stripped-down base image. Install it there by hand instead - "
            "whichever of these fits that machine: sudo apt-get install -y python3-psutil (Debian/Ubuntu), "
            "sudo dnf install -y python3-psutil (Fedora/RHEL), or python3 -m pip install "
            "--break-system-packages psutil, then run Setup again.")


#Define FLAG_FOR_ACTION, the small lookup table dispatch() below uses for
#every action that is just "run poltergeist.py with one fixed flag" - the
#ones that need no extra typed input at all.
FLAG_FOR_ACTION = {
    "scan": "--quickscan",
    "baseline": "--baseline",
    "canaries": "--canaries",
    "oracle": "--oracle",
    "snapshot": "--snapshot",
}


#Define _maybe_elevate_remote_command, which wraps a remote shell command
#with "sudo -S -p ''" - reusing the SAME SSH password already typed in for
#login, exactly like the psutil-installer fallback above, and exactly like
#the Shadow Watch/Harbinger tool this whole investigation was compared
#against does for its OWN scans (its start.py "ask once, reuse it" sudo
#check, and orchestrator.py's own privileged scan commands).
#
#Why this needs to exist at all: Poltergeist's "deploy & run yourself"
#model means the remote machine runs its own full copy of this codebase as
#a plain background process - under whatever account logged in over SSH,
#with NO elevation at all, unlike running locally where a person decides
#for themselves whether to launch with sudo/as Administrator. On a real
#target that matters a lot: reading /root/.ssh (quickscan.py's own SSH-key
#check), seeing full process detail for processes owned by OTHER users
#(processes.py/persistence.py), and some root-only files under
#/etc/systemd/system all silently come back empty for a non-root user -
#not because nothing is there, but because the deployed scan was never
#allowed to look. That is exactly what made the Dashboard show
#"(nothing to report)" on a box the reference tool found plenty on: the
#reference tool was elevating every scan with sudo, and this one was not.
#
#Only a password-auth target with a password actually in hand can do
#this - a key-file or agent/default target has no password for Poltergeist
#to reuse, so those still run unprivileged (same reduced-visibility
#situation as running locally without root/Administrator - see cli.py's
#own local warning for that case, and probe_target_remote()'s one-time
#note below for the remote equivalent of it).
def _maybe_elevate_remote_command(target, secret, remote_command):
    if target.get("auth_mode") == "password" and secret.get("password"):
        #sudo -S reads exactly one line from stdin then stops, so hand it
        #one. -p '' suppresses sudo's own "[sudo] password for x:" prompt
        #text, which would otherwise show up mixed into real scan output.
        #Wrap the WHOLE existing command (which already resolves python3
        #and cd's into the deployed folder) inside sh -c, quoted as one
        #argument, so everything in it runs AS ROOT - not just a bare
        #"sudo poltergeist.py" that would still cd/resolve python3 as the
        #unprivileged login user before sudo ever takes effect.
        elevated_command = f"sudo -S -p '' sh -c {shlex.quote(remote_command)}"
        return elevated_command, secret["password"] + "\n"
    #No password available to elevate with - run exactly as given.
    return remote_command, None


#Define _test_remote_elevation, which probe_target_remote() below calls
#ONCE, at Setup time, to find out (and tell the person right away) whether
#sudo elevation is actually going to work on this target - rather than
#silently finding out via a confusing dashboard full of "(nothing to
#report)" sections after the fact, which is exactly the bug report that
#led to this function existing. Runs one harmless, read-only command
#("id -un") elevated, and checks that it actually came back as root.
def _test_remote_elevation(config, target, secret):
    #Key-file/agent targets have no password to reuse at all - say so
    #plainly and do not even attempt it.
    if target.get("auth_mode") != "password" or not secret.get("password"):
        return False, (
            "this target logs in with a key/agent, not a password, so Poltergeist has no "
            "password to reuse for sudo. Scans will run as whatever account logs in over SSH "
            "and may miss anything that needs root to see (SSH keys under /root, full detail "
            "on processes owned by other users, some root-only files). For full visibility, "
            "either switch this target to username+password auth, or give that login account "
            "passwordless sudo (NOPASSWD) on the remote machine."
        )
    #Build the elevated form of the simplest possible command.
    elevated_command, stdin_text = _maybe_elevate_remote_command(target, secret, "id -un")
    try:
        success, output = run_remote_command_capture(config, target, secret, elevated_command, timeout=15, stdin_text=stdin_text)
    except Exception as exc:
        return False, f"could not test sudo elevation: {describe_connect_error(exc)}"
    if success and "root" in output:
        #Confirmed: sudo actually elevates to root with this password.
        return True, ""
    #Ran, but did not actually become root - probably a wrong/missing
    #sudo password (it does not have to match the SSH login password,
    #even though it usually does) or the account has no sudo rights at all.
    return False, (
        "sudo did not elevate to root with the SSH login password (got: "
        f"{output.strip()[:150] or '(nothing printed)'}). Scans will run unprivileged and may "
        "miss anything that needs root to see. If this account's sudo password differs from "
        "its SSH login password, or it has no sudo rights at all, that is why."
    )


#Define dispatch, the ONE function cli.py's unified run_action() calls for
#a remote target, for every single action key the local side can run.
#It builds the matching remote command, runs it (streaming its output
#live), and then always pulls evidence back afterward, so the local
#findings table/Dashboard/Scribe never fall out of sync with what the
#remote side actually just did.
def dispatch(config, target, secret, action_key, extra_input=None):
    #Work out the label used on every printed line.
    label = target.get("label") or target.get("host", "remote")
    #Work out the remote folder this target was deployed to.
    remote_root = target.get("remote_path") or "poltergeist"
    #shlex.quote() the remote_path once up front, since it goes into every
    #branch below's "cd" command.
    quoted_root = shlex.quote(remote_root)
    #Branch on which action is actually being asked for.
    if action_key in FLAG_FOR_ACTION:
        #A plain fixed flag, no extra input needed.
        remote_command = f"{_PYTHON3_RESOLVE}; cd {quoted_root} && \"$PY3\" poltergeist.py {FLAG_FOR_ACTION[action_key]}"
    elif action_key == "tripwire_add":
        #Needs one extra piece of input: which folder to watch. Quote it,
        #since a real folder path can easily contain spaces.
        remote_command = f"{_PYTHON3_RESOLVE}; cd {quoted_root} && \"$PY3\" poltergeist.py --watch {shlex.quote(extra_input or '')}"
    elif action_key == "tripwire_remove":
        #The direct counterpart to tripwire_add above - which folder to
        #STOP watching, same quoting reasoning.
        remote_command = f"{_PYTHON3_RESOLVE}; cd {quoted_root} && \"$PY3\" poltergeist.py --unwatch {shlex.quote(extra_input or '')}"
    elif action_key == "canary_add":
        #Needs one extra piece of input: which folder to seed with bait
        #files - the Canary equivalent of tripwire_add just above.
        remote_command = f"{_PYTHON3_RESOLVE}; cd {quoted_root} && \"$PY3\" poltergeist.py --seed {shlex.quote(extra_input or '')}"
    elif action_key == "canary_remove":
        #The direct counterpart to canary_add above - which folder to
        #STOP seeding, same quoting reasoning.
        remote_command = f"{_PYTHON3_RESOLVE}; cd {quoted_root} && \"$PY3\" poltergeist.py --unseed {shlex.quote(extra_input or '')}"
    elif action_key == "snapshot_revert":
        #Needs one extra piece of input: which folder to revert, the
        #Medium equivalent of tripwire_add/canary_add above. The typed
        #RESTORE confirmation already happened on the CALLER's side (the
        #GUI's own "revert_folder" dialog flow, or the CLI's own
        #--revert-confirm check) before dispatch() was ever reached, so
        #there is nothing left to confirm way out here.
        remote_command = f"{_PYTHON3_RESOLVE}; cd {quoted_root} && \"$PY3\" poltergeist.py --revert {shlex.quote(extra_input or '')}"
    elif action_key == "shield_rule":
        #Needs the typed rule text, which can also contain spaces.
        remote_command = f"{_PYTHON3_RESOLVE}; cd {quoted_root} && \"$PY3\" poltergeist.py --shield {shlex.quote(extra_input or '')}"
    elif action_key == "shield_mute":
        #The confirmation word is always the literal "MUTE" by this point
        #(the caller already made the human type it to get here), so there
        #is nothing variable to quote.
        remote_command = f"{_PYTHON3_RESOLVE}; cd {quoted_root} && \"$PY3\" poltergeist.py --mute MUTE"
    else:
        #Not one of the actions this module knows how to run remotely.
        print(f"  [{label}] '{action_key}' is not a recognized remote action")
        #Return False so the caller knows nothing ran.
        return False
    #Elevate with sudo if we can (password-auth target, password in hand) -
    #see _maybe_elevate_remote_command()'s own comment for why this is the
    #actual fix for "the Dashboard shows nothing on a box that has plenty
    #on it": every scan/action command above was running fully unprivileged
    #with no elevation anywhere, so this is where that gets corrected.
    remote_command, stdin_text = _maybe_elevate_remote_command(target, secret, remote_command)
    #Open ONE connection for this whole dispatch - the command AND the
    #evidence pull that follows it both run over this same connection,
    #instead of each opening (and authenticating) its own brand new one.
    #This is deliberate, not an optimization afterthought: a competition
    #box's own SSH server commonly throttles/rate-limits how many NEW
    #connections one source IP can open per minute (exactly the kind of
    #defense this tool teaches its users to set up), and the old
    #two-connections-per-scan-cycle behavior was easily enough on its own
    #to trip that, even though every single connection used the right
    #password - which is what a real "it just freezes, authentication
    #failed, over and over" report traced back to: the SECOND connection
    #(the evidence pull) kept getting refused moments after the FIRST one
    #(the command) had just authenticated fine. If opening the connection
    #itself fails, run_remote_command()'s own no-client fallback path
    #below still reports a clear error exactly like before.
    try:
        client = connect(config, target, secret)
    except Exception as exc:
        #Could not even open the shared connection - explain why and stop
        #here, the same clear message run_remote_command() would have
        #given on its own if it had tried and failed.
        print(f"  [{label}] could not connect: {describe_connect_error(exc)}")
        return False
    try:
        #Actually run the built command, streaming its output live, over
        #the connection we just opened.
        succeeded = run_remote_command(config, target, secret, remote_command, label=label,
                                        stdin_text=stdin_text, existing_client=client)
        #Pull evidence back afterward regardless of the exact outcome
        #above - this is cheap, idempotent, and means a partial success
        #(the command ran but one line failed, say) still gets reflected
        #locally. Reuses the SAME connection - no second login.
        pull_evidence(config, target, secret, existing_client=client)
    finally:
        #Close the one connection this whole dispatch actually used.
        client.close()
    #Hand back whether the action itself reported success.
    return succeeded
