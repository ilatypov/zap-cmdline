#!/usr/bin/env python
# vim: et:ts=4:sts=4:sw=4:fileencoding=utf-8
ur"""
Spider, AJAX spider and active scan a URL.
"""

import sys
import subprocess
import os
import signal
import time
import json
import string
import logging
import inspect
import urllib

sys.path.insert(1, "./lib")
from zapv2 import ZAPv2

log = logging.getLogger(__name__)

class ZapCmdException(Exception):
    pass

class AutoFlush:
    def __init__(self, out):
        self._out = out

    def write(self, s):
        self._out.write(s)
        self._out.flush()

    def __getattr__(self, attrname):
        return getattr(self._out, attrname)


def autoflush_output():
    if not isinstance(sys.stdout, AutoFlush):
        sys.stdout = AutoFlush(sys.stdout)
    if not isinstance(sys.stderr, AutoFlush):
        sys.stderr = AutoFlush(sys.stderr)


def utc_offset(s_since_epoch=None):
    r"""
    Find the local UTC offset of the moment given by s_since_epoch or using the
    current time.
    
    http://stackoverflow.com/questions/13218506/how-to-get-system-timezone-setting-and-pass-it-to-pytz-timezone#comment25200533_13218990
    """
    is_dst = time.daylight and time.localtime(s_since_epoch).tm_isdst
    zone = time.altzone if is_dst else time.timezone
    # tzname = "Etc/GMT%+d" % (zone / 3600,)
    return -zone


def strftime_with_utc_offset(datefmt=None, t=None):
    if t is None:
        s_since_epoch = time.time()
    elif isinstance(t, (tuple, time.struct_time)):
        s_since_epoch = time.mktime(t)
    else:
        s_since_epoch = t

    if datefmt is None:
        text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(s_since_epoch))
    elif "%" in datefmt:
        text = time.strftime(datefmt, time.localtime(s_since_epoch))
    else:
        text = datefmt

    utcoff = utc_offset(s_since_epoch)
    if utcoff > 0:
        utcsign = "+"
    else:
        utcsign = "-"
        utcoff = -utcoff
    return text + ("%s%02d%02d" % (utcsign, utcoff / 3600, (utcoff % 3600) / 60))


def python2_logging_handler_formatter_tz_fix():
    formatter_instance = logging.getLogger().handlers[-1].formatter
    origBoundMethod = formatter_instance.formatTime
    def tzFormatTime(record, datefmt=None):
        return strftime_with_utc_offset(origBoundMethod(record, datefmt=datefmt), record.created)
    formatter_instance.formatTime = tzFormatTime


def utclogging_config(level):
    frame = inspect.stack()[1]
    module = inspect.getmodule(frame[0])
    if hasattr(utclogging_config, "firstCaller"):
        warnings.warn(__file__ + 
                ": After configuring logging in %s, ignoring another configuration in %s\n" % (utclogging_config.firstCaller, 
            module.__file__,),
            RuntimeWarning, 2)
        return
    utclogging_config.firstCaller = module.__file__
    autoflush_output()
    logging.basicConfig(format="%(asctime)s %(levelname)s %(name)s.%(funcName)s %(message)s", level=level)
    python2_logging_handler_formatter_tz_fix()


def cut(s, w):
    s = str(s)
    if len(s) > (w - 3):
        s = s[:w - 3] + "..."
    return s


taskkillexe = os.getenv("WINDIR").replace("\\", "/") + "/system32/taskkill.exe"

def terminate_process_tree(pid=None, image=None):
    try:
        cmd = ["taskkill.exe", "/f", "/t"]
        if pid is not None:
            cmd.extend(("/pid", str(pid)))
        else:
            cmd.extend(("/im", image))
        output = subprocess.check_output(cmd,
                executable=taskkillexe,
                shell=False,
                stderr=subprocess.STDOUT)
        log.info("Terminating: %s" % (output,))
    except subprocess.CalledProcessError as ex:
        log.info("Terminating: return code %d, %s" % (ex.returncode, ex.output))


def pentest(owaspzap, target, httpUsername, httpPassword):
    # Configuration
    #browser='firefox'
    browser="phantomjs"

    phantomJSPath = "c:/selenium-drivers/phantomjs.exe"
    log.info("Using PhantomJS binary path " + phantomJSPath)

    # Start zap.
    zapProxyHost = '127.0.0.1'
    zapProxyPort = 8090
    zapProxy = "%s:%d" % (zapProxyHost, zapProxyPort)
    executable = os.getenv("JAVA_HOME") + "\\bin\\java.exe"
    log.info("Starting ZAP proxying on %s with %s" % (zapProxy, executable,))
    proc = subprocess.Popen([executable, "-jar", owaspzap + "\\zap-2.5.0.jar",
            "-daemon",
            "-config", "api.disablekey=true",
            "-config", "ajaxSpider.browserId=" + browser,
            "-config", "selenium.phantomJsBinary=" + phantomJSPath,
            "-host", zapProxyHost,
            "-port", str(zapProxyPort),], 
        executable=executable.replace("\\", "/"),
        shell=False,                        # Not using CMD lets us catch the PID of java.exe instead of CMD.EXE.
                                            # When Cygwin shell terminated the native process CMD.EXE on Ctrl-C, 
                                            # we lost track of the spawned java.exe.
        cwd=owaspzap)

    try:
        log.info("Waiting for ZAP to load in a process tree starting with pid " + str(proc.pid))

        # Wait until the ZAP API is reachable.
        zap = ZAPv2(proxies={"http": "http://%s" % (zapProxy,), "https": "http://%s" % (zapProxy,)})
        while True:
            try:
                version = zap.core.version
            except:
                log.info('ZAP not running yet, waiting.')
                time.sleep(1)
            else:
                # Wait a bit more for ZAP to fully start.
                log.info('Connected to ZAP version ' + version)
                break

        time.sleep(1)

        # https://groups.google.com/d/msg/zaproxy-users/BrVE0Zp_ug4/8PST56_-5nQJ
        # https://janitha000.wordpress.com/2015/09/12/owasp-zap-authentication-and-command-line-tool/
        log.info("Setting a context")
        ctxname = "zapcmd"
        cid = zap.context.new_context(ctxname)
        zap.context.include_in_context(ctxname, target + ".*")

        log.info("Configuring form authentication")
        zap.authentication.set_authentication_method(cid, "formBasedAuthentication", 
                authmethodconfigparams = "loginUrl=" + target + 
                    "/j_spring_security_check&loginRequestData=username%3D%7B%25username%25%7D%26password%3D%7B%25password%25%7D")
        zap.authentication.set_logged_in_indicator(cid, "href=\"j_spring_security_logout\"")
        # zap.authentication.set_logged_out_indicator(cid, "Location: http\\.*/WebGoat/login\\.mvc|\\Qhref=\"login\\.mvc\"\\E|onload=\"document.loginForm.username.focus();\"")
        zap.authentication.set_logged_out_indicator(cid, "onload=\"document.loginForm.username.focus();\"")
        
        username = "guest"
        password = "guest"
        useridname = "guestid"
        userid = zap.users.new_user(cid, useridname)
        zap.users.set_user_name(cid, userid, username)
        zap.users.set_authentication_credentials(cid, userid, "username=%s&password=%s" % ( urllib.quote(username), 
            urllib.quote(password)))
        zap.users.set_user_enabled(cid, userid, True)

        zap.forcedUser.set_forced_user(cid, userid)
        zap.forcedUser.set_forced_user_mode_enabled(True)

        log.info("Created context " + str(cid) + ": " + str(zap.context.context(ctxname)))
        log.info("Auth method: " + str(zap.authentication.get_authentication_method(cid)))

        log.info('Accessing target %s' % target)
        # htmlResult = zap.urlopenWithPassword(target, httpUsername, httpPassword)
        htmlResult = zap.core.access_url(target + "/welcome.mvc", followredirects=True)
        log.info("Received HTML: " + ", ".join(cut(r["requestHeader"], 70).replace("\n", "\\n").replace("\r", "\\r") 
            for r in htmlResult))

        # Give the sites tree a chance to get updated
        time.sleep(2)

        # Spider the target.
        for spiderscan in zap.spider.scans:
            log.info("Spider scan: " + str(spiderscan))

        log.info('Spidering target %s' % target)
        scanid = zap.spider.scan_as_user(cid, userid, recurse=True, subtreeonly=True)
        try:
            scanidnum = int(scanid)
        except ValueError as ex:
            log.info("Unexpected spider scan ID \"" + scanid + "\"")
            raise
        log.info("Spider scan ID: " + str(scanid))
        time.sleep(2)

        while True:
            status = zap.spider.status(scanid)
            log.info("Spider progress: " + status)
            if status == "100":
                break
            time.sleep(2)

        log.info("Spider completed")
        # Give the spider some time to finish.
        time.sleep(2)

        for spiderscan in zap.spider.scans:
            log.info("Spider scan: " + str(spiderscan))

        for result in zap.spider.results(scanid):
            log.info("Spider result: " + str(result))

        log.info("Total of " + str(len(zap.core.urls)) + " URLs")

        # Start the AJAX spider.  TODO: use form authentication.
        log.info("AJAX %s spidering target %s" % (zap.ajaxSpider.option_browser_id, target,))
        zap.ajaxSpider.scan_as_user(ctxname, username, url=target)

        # Wait for AJAX spider to complete.
        while True:
            status = zap.ajaxSpider.status
            log.info('AJAX spider ' + status + ', number of results: ' + zap.ajaxSpider.number_of_results)
            if status != 'stopped':
                break
            time.sleep(1)

        log.info('AJAX Spider completed')
        # Give the AJAX spider some time to finish.
        time.sleep(3)

        num_urls = len(zap.core.urls)
        if (num_urls == 0):
          raise ZapCmdException("No URLs found - is the target URL \"" + target + "\"accessible?")
        log.info("Total of " + str(len(zap.core.urls)) + " URLs")

        for result in zap.ajaxSpider.results():
            bDetail = result["requestBody"]
            if len(bDetail) > 0:
                bDetail = " (%s)" % (cut(bDetail, 20))
            log.info("AJAX result: " + (cut(result["requestHeader"], 70) + bDetail).encode("utf-8").encode("string_escape"))

        log.info('Scanning target %s' % target)
        ascanid = zap.ascan.scan_as_user(target, cid, userid, recurse=True)
        log.info("Active scan ID: " + str(ascanid))

        while True:
            status = zap.ascan.status(ascanid)
            log.info('Active scan ' + status)
            if status == "100":
                break
            time.sleep(5)

        alerts = zap.core.alerts()
        log.info('Active scan completed, number of alerts: ' + str(len(alerts)))

        # Gather results.
        alerts_jsonrepr = json.dumps(alerts)

        # Write the results to disk.
        f = open('report.json', 'w')
        f.write(str(alerts_jsonrepr))
        f.close()

        # Shutdown ZAP.
        zap.core.shutdown()
    finally:
        # Terminate the browser process spawned by ZAP daemon.
        #
        # Now that we spawn java.exe directly rather than through cmd.exe,
        # Cygwin bash terminates java.exe on our pressing Ctrl-C, relieving us
        # from having to clean up the process ourselves.
        #
        # Just in case any other error throws an exception, let's
        # terminate java.exe quietly.
        #
        ## The Cygwin build of Python has no signal.CTRL_C_EVENT
        ## os.kill(proc.pid, signal.CTRL_C_EVENT)
        #
        log.info("Terminating trees of %s.exe and PID %d" % (browser, proc.pid))
        terminate_process_tree(image=browser + ".exe")
        terminate_process_tree(pid=proc.pid)

if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) >= 2 and args[0] == "-v":
        verbose = True
        del args[:1]
    else:
        verbose = False
    utclogging_config(logging.DEBUG if verbose else logging.WARNING)

    # Check command line arguments.
    if len(args) < 2:
        log.info('Usage: python zap-cmdline.py OWASP_DIR URL [HTTP_USER HTTP_PASSWORD].')
        sys.exit(2)

    # Use first parameter as URL to scan.
    owaspzap = args[0]
    target = args[1]
    httpUsername = None
    httpPassword = None
    if len(args) == 4:
        httpUsername = sys.argv[2]
        httpPassword = sys.argv[3]
        target = string.replace(target, '://', '://' + httpUsername + ':' + httpPassword + '@')

    pentest(owaspzap, target, httpUsername, httpPassword)

