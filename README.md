# Screems 

Screems is a web socket based file streamer. 

## Why?

Getting a file is easy, you can:
1. Download the file over http
1. rsync
1. scp
1. etc

## How does it work?

Screems uses Tornado for web socket and http communication:

 Client --> WebSocket Connection ----> Server
 Client --> JSON { filename: blabla } --> Server 
 Client <---- File streamed <---- Server

