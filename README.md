# Screems 

Screems is a web socket based file streamer. 

## Why?

Getting a file is easy, you can:

1. Download the file over http
1. rsync
1. scp
1. etc

But sometimes you don't want a copy of a file, you want to watch log files being updated in real time. 
Maybe you don't have access to the server that contains the log files. Now you can stream the
file and see all the updates.

## How does it work?

Screems uses Tornado for web sockets and http communication:

 Client --> WebSocket Connection ----> Server
 
 Client --> JSON { filename: bla_bla } --> Server 
 
 Client <---- File streamed <---- Server

## Usage

On the server:

python screems.py --dir /home/usertest --file /var/log/httpd/access.log

Then on a client machine:

wsdump.py ws:/<server-name>:8888/ws

and send a JSON message requesting a certain file, like:

- { "filename":"testfile.txt" }
- { "filename":"/var/log/httpd/access.log" }

The system will look for testfile.txt in all the directories specified by --dir on the server.

## Demo Client

There is a Javascript websocket streaming app available at <hostname>:<port>/jsviewer that you can point a browser to and watch it update.
