import argparse
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


def parse_cmd_line(argv):
    """
    Parse command line arguments

    argv: Pass in cmd line arguments
    """

    if sys.platform == "linux":
        syslog_location = "/dev/log"
    elif sys.platform == "osx":
        syslog_location = "/var/run/syslog"
    else:
        syslog_location = ('localhost',514)

    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", help="Enable debugging", action="store_true")
    parser.add_argument("-v", "--verbose", help="Enable verbose logging", action="store_true")
    parser.add_argument("-p", "--port", help="Server port to run on", default=8888)
    parser.add_argument("--dirs", help="Directories to serve from the web interface")
    parser.add_argument("--files", help="Specific files to serve from the web interface")
    parser.add_argument("--wait", help="Specify how long to watch a file for new data", default=300)
    parser.add_argument("-k", "--kill", help="Kill previous instance running in the background", action="store_true")
    parser.add_argument("--background", help="Run in background", action="store_true")
    parser.add_argument("--syslog", help="Send logs to syslog location", default=syslog_location)

    args = parser.parse_args()
    if args.dirs == None:
        args.dirs = []
    else:
        args.dirs = args.dirs.split(',')
    
    if args.files == None:
        args.files = []
    else:
        args.files = args.files.split(',')

    return args


def set_logging(cmd_options):
    """
    Setup logging and format output
    """
    log = logging.getLogger("%s" % (LOG_NAME))
    log_level = logging.INFO
    log_level_console = logging.WARNING

    if cmd_options.verbose:
        log_level_console = logging.INFO

    if cmd_options.debug:
        log_level_console = logging.DEBUG
        log_level = logging.DEBUG

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    sys_formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')

    console_log = logging.StreamHandler()
    console_log.setLevel(log_level_console)
    console_log.setFormatter(formatter)

    syslog_hndlr = SysLogHandler(
        address=cmd_options.syslog,
        facility=SysLogHandler.LOG_USER
        )

    syslog_hndlr.setFormatter(sys_formatter)

    log.setLevel(log_level)
    log.addHandler(console_log)
    log.addHandler(syslog_hndlr)

    access_log = logging.getLogger("tornado.access")
    access_log.setLevel(log_level)
    access_log.addHandler(console_log)
    access_log.addHandler(syslog_hndlr)

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
        # TODO: add support for changing port
        # TODO: add support for setting fqdn
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

    def _combine_path(self, safe_dir, requested_file):
        return os.path.join(safe_dir, rest)

    def _cleanse_path(self, requested_file):
        # Prevent nefarious pathname manipulations.
        rest = os.path.normpath(requested_file)
        rest = rest.lstrip('/')
        rest = rest.lstrip('../')
        return rest

    def _check_path(self, requested_file):
        if os.path.exists(requested_file) and os.path.isfile(requested_file):
            return True
        else:
            return False


    def _on_data(self):
        pass

    def on_message(self, message):
        # Find and serve the path requested in the message.
        found = False
        absolute_path = None

        for safe_file in OPTIONS.files:
            absolute_path = self._cleanse_path(message)
            if self._check_path(absolute_path):
                found = True
                break

        for safe_dir in OPTIONS.dirs:
            path = self._cleanse_path(message)
            absolute_path = self._combine_path(safe_dir, path)
            if os.path.exists(path) and os.path.isfile(path):
                found = True
                break
                
        if not found:
            log.warning("Requested file not found: %s" % (absolute_path))
            self.write_message("File not found: %s" % (message))

        self.filename = absolute_path
        self._on_data()

    def on_close(self):
        log.info("Connection closed")


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

    if options.kill:
        send_shutdown(pid_file)
        sys.exit(0)

    # Setup signal to catch Control-C / SIGINT and SIGTERM
    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    log.debug("Using settings:")
    log.debug(str(options))
    
    application = tornado.web.Application([
            (r'/js', JavascriptHandler),
            (r'/ws', WebsocketHandler),
            ])


    if options.background:
        log.info("Starting in background ...")
        my_daemon = MyDaemon(pid_file, options)
    else:
        log.info("Starting ...")

    if my_daemon:
        options.tornado_application = application
        my_daemon.start()
    else:
        application.listen(options.port)
        tornado.ioloop.IOLoop.instance().start()


class MyDaemon(daemon.daemon):
    def run(self):
        application = self.options.tornado_application
        log.debug("Background Daemon: Listening on socket")
        application.listen(self.options.port)
        log.debug("Background Daemon: Starting IOLOOP")
        tornado.ioloop.IOLoop.instance().start()



if __name__ == "__main__":
    result = main()
    sys.exit(result)


