Fail2Ban Referer Spam Blacklist
===============================

This is a community-contributed list of [referer spam domains](http://en.wikipedia.org/wiki/Referer_spam)

This repository is a fork of [desbma's referrer spam blacklist](https://github.com/desbma/referer-spam-domains-blacklist).

You need to edit `/etc/fail2ban/jail.conf`, to locate the Apache logs, and configure ban time:

    [apache-referer]
    enabled = true
    maxretry = 1
    port = http,https
    filter = apache-referer
    logpath = /var/log/apache*/*access.log

I changed some things to fit personal purposes:

* more referer domains added (taken by private darklist.de project)
* changed update script to use git without many bash operations
* added get new spammers script to identify new spammers from apache logs

## License

[WTFPLv2](http://www.wtfpl.net/txt/copying/)
