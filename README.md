# http-flowripper.pl

Takes input from tcpflow -c and rips out HTTP info.

Multiple parallel connections, mutliple users from one source IP, and
other fun factors make troubleshooting some web apps a bear.  If you
can't use a debugging/capturing proxy like OWASP's WebScarab,
http-flowripper.pl is here to help.

