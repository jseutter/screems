import os
import sys
import time
import datetime
import logging
import json
import signal
from os.path import expanduser
from logging.handlers import *


import tornado.ioloop
import tornado.web
import tornado.websocket


SCRIPT_NAME = os.path.basename(__file__)

#Is the full path when used as an import
SCRIPT_PATH = os.path.dirname(__file__)

if not SCRIPT_PATH:
    SCRIPT_PATH = os.path.join(os.path.dirname(os.path.abspath(
        sys.argv[0])))


EXTRA_LIB = "%s/libs" % (SCRIPT_PATH)


LOG_NAME = "%s" % (SCRIPT_NAME)
OPTIONS = {}

log = None

sys.path.append(EXTRA_LIB)

import daemon

my_daemon = None 

usage = """
USAGE: %s

Options:

  -d, --debug         Enable debugging
  -v, --verbose       Enable verbose logging
  -h, --help          Display this menu :)
  
  -p, --port          Server port to run on

  --dir=<dirs>        Directory that are accessible from the web interface
  --file=file         Specific files available from the web interface
  
  -k                  Kill previous instance running in background
  --background        Run in background

""" % (SCRIPT_NAME)

# Parse cmd line options
def parse_cmd_line(argv):
    """
    Parse command line arguments

    argv: Pass in cmd line arguments
    """

    options = {}
    options["debug"] = False
    options["verbose"] = True
    options["port"] = 8888
    options["safe_dirs"] = ["/tmp"]
    options["safe_files"] = []
    options["shutdown"] = False
    options["daemon"] = False
    return options


def set_logging(cmd_options):
    """
    Setup logging and format output
    """
    log = logging.getLogger("%s" % (LOG_NAME))
    log_level = logging.INFO
    log_level_console = logging.WARNING

    if cmd_options['verbose'] == True:
        log_level_console = logging.INFO

    if cmd_options['debug'] == True:
        log_level_console = logging.DEBUG
        log_level = logging.DEBUG

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    sys_formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')

    console_log = logging.StreamHandler()
    console_log.setLevel(log_level_console)
    console_log.setFormatter(formatter)

#    syslog_hndlr = SysLogHandler(
#        address=cmd_options['syslog'],
#        facility=SysLogHandler.LOG_USER
#    )

#    syslog_hndlr.setFormatter(sys_formatter)

    log.setLevel(log_level)
    log.addHandler(console_log)
#    log.addHandler(syslog_hndlr)

    access_log = logging.getLogger("tornado.access")
    access_log.setLevel(log_level)
    access_log.addHandler(console_log)
#    access_log.addHandler(syslog_hndlr)

    return log

def send_shutdown(pid_file):
    try:
        with open(pid_file, 'r') as pidf:
            pid = int(pidf.readline().strip())
            pidf.close()
            os.kill(pid, 15)
    except:
        log.info("No running instance found!!!")
        log.info("Missing PID file: %s" % (pid_file))


class JavascriptHandler(tornado.web.RequestHandler):
    def get(self):
        self.write("Hello world")

    def get(self):
        self.write("""
<html>
<body>
<script>
var ws = new WebSocket("ws://localhost:8888/ws");
ws.onopen = function() {
  ws.send("/hello.txt");
};
ws.onmessage = function (evt) {
   document.body.innerHTML = evt.data;
};
</script>
</body>
</html>
"""        )


class WebsocketHandler(tornado.websocket.WebSocketHandler):
    def open(self):
        print("WebSocket opened")

    def _cleanse_path(self, safe_dir, rest):
        # Prevent nefarious pathname manipulations.
        # TODO: Add tests for validity
        rest = os.path.normpath(rest)
        rest = rest.lstrip('/')
        rest = rest.lstrip('../')
        path = os.path.join(safe_dir, rest)
        return path

    def on_message(self, message):
        found = False
        for safe_dir in OPTIONS['safe_dirs']:
            path = self._cleanse_path(safe_dir, message)
            if os.path.exists(path) and os.path.isfile(path):
                found = True
                contents = open('/tmp/' + message, 'r').read()
                self.write_message(contents)
                break
        # TODO: Handle file not found condition.
        if not found:
            print("File %s not found" % message)

    def on_close(self):
        print("WebSocket closed")


def main():

    global log
    global my_daemon
    global OPTIONS
    options = parse_cmd_line(sys.argv)
    OPTIONS = options
    log = set_logging(options)   

    def _shutdown(signalnum=None, frame=None):
        """
        Handles the SIGINT and SIGTERM event, inside of main so it has access to
        the log vars.
        """

        log.warning("Received shutdown signal")
        tornado.ioloop.IOLoop.instance().stop()
        log.warning("IO stopped")

    pid_file = "%s/.%s.pid" % (expanduser("~"), SCRIPT_NAME)

    if options["shutdown"]:
        send_shutdown(pid_file)
        sys.exit(0)

    # Setup signal to catch Control-C / SIGINT and SIGTERM
    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    log.debug("Using settings:")
    for key, value in iter(sorted(options.items())):
        log.debug("%s : %s" % (key, value))
    
    application = tornado.web.Application([
            (r'/js', JavascriptHandler),
            (r'/ws', WebsocketHandler),
            ])


    if options["daemon"]:
        log.info("Starting in background ...")
        my_daemon = MyDaemon(pid_file, options)
    else:
        log.info("Starting ...")

    if my_daemon:
        options["tornado_application"] = application
        my_daemon.start()
    else:
        application.listen(options["port"])
        tornado.ioloop.IOLoop.instance().start()


class MyDaemon(daemon.daemon):
    def run(self):
        application = self.options["tornado_application"]
        log.debug("Background Daemon: Listening on socket")
        application.listen(self.options["port"])
        log.debug("Background Daemon: Starting IOLOOP")
        tornado.ioloop.IOLoop.instance().start()



if __name__ == "__main__":
    result = main()
    sys.exit(result)


