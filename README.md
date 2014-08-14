# Screems 

Screems is a web socket based file streamer. 

## Why?

Getting a file is easy, you can:

1. Download the file over http
1. rsync
1. scp
1. etc

But sometimes you don't want a copy of a file, you want to watch log files being updated in real time. 
Maybe you don't have access to the server that contains the log files. Now you can watch / stream the
file and see all the updates.

## How does it work?

Screems uses Tornado for web socket and http communication:

 Client --> WebSocket Connection ----> Server
 
 Client --> JSON { filename: blabla } --> Server 
 
 Client <---- File streamed <---- Server

