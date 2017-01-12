#!/usr/bin/env python
# vim: et:ts=4:sts=4:sw=4:fileencoding=utf-8
ur"""
Spider, AJAX spider and active scan a URL.
"""

import sys
import subprocess
import os
import time
import json
import string
import logging
import inspect

sys.path.insert(1, "./lib")
from zapv2 import ZAPv2

log = logging.getLogger(__name__)

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


def pentest(owaspzap, target, httpUsername, httpPassword):
    # Configuration
    #browser='firefox'
    browser='phantomjs'

    phantomJSPath = "c:/selenium-drivers/phantomjs.exe"
    log.info('Using PhantomJS binary path ' + phantomJSPath)

    # Start zap.
    log.info('Starting ZAP as ' + owaspzap + '\zap.bat')
    # subprocess.Popen(['c:/cygwin64/bin/bash.exe', 'c:/Program Files (x86)/OWASP/Zed Attack Proxy/zap.sh','-daemon','-config','api.disablekey=true','-config','ajaxSpider.browserId='+browser,'-config','selenium.phantomJsBinary=' + phantomJSPath])
    subprocess.Popen([owaspzap + '\zap.bat',
        '-daemon',
        '-config', 'api.disablekey=true',
        '-config', 'ajaxSpider.browserId=' + browser,
        '-config', 'selenium.phantomJsBinary=' + phantomJSPath,
        '-host', '127.0.0.1',
        '-port', '8090',])

    log.info('Waiting for ZAP to load.')

    # Wait until the ZAP API is reachable.
    version = ''
    zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8090', 'https': 'http://127.0.0.1:8090'})
    while (version == ''):
        try:
            version = zap.core.version
        except:
            log.info('ZAP not running yet, waiting.')
            time.sleep(1)
        else:
            # Wait a bit more for ZAP to fully start.
            log.info('Got ZAP version ' + version)
            time.sleep(1)

    # Ready for business ;-)
    log.info('ZAP version ' + version + ' is running.')

    # Connect to the target.
    log.info('Accessing target %s' % target)
    htmlResult = zap.urlopenWithPassword(target, httpUsername, httpPassword)
    log.info('Received HTML: ' + htmlResult)

    # Give the sites tree a chance to get updated
    time.sleep(2)

    # Spider the target.
    log.info('Spidering target %s' % target)
    zap.spider.scan(target)
    time.sleep(2)
    while (int(zap.spider.status()) < 100):
        log.info('Spider progress %: ' + zap.spider.status())
        time.sleep(2)

    log.info('Spider completed')
    # Give the spider some time to finish.
    time.sleep(2)


    # Start the AJAX spider.
    log.info('AJAX spidering target %s' % target)
    zap.ajaxSpider.scan(target)

    # Wait for AJAX spider to complete.
    while (zap.ajaxSpider.status != 'stopped'):
        log.info('AJAX spider ' + zap.ajaxSpider.status + ', ' + zap.ajaxSpider.number_of_results + ' results.')
        time.sleep(1)

    log.info('AJAX Spider completed')
    # Give the AJAX spider some time to finish.
    time.sleep(3)

    for result in zap.ajaxSpider.results():
        log.info("AJAX result: " + str(result))

    log.info('Scanning target %s' % target)
    zap.ascan.scan(target)
    while (int(zap.ascan.status()) < 100):
        log.info('Scan progress %: ' + zap.ascan.status())
        time.sleep(5)

    log.info('Scan completed')

    # Gather results.
    results = json.dumps(zap.core.alerts())

    # Write the results to disk.
    f = open('report.json', 'w')
    f.write(str(results))
    f.close()

    # Shutdown ZAP.
    zap.core.shutdown()


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


