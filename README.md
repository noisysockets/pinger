# pinger

A cross platform unprivileged Ping (ICMP Echo) library for Go.

This is achieved by shelling out to the systems `ping` command. Yes this is a
little bit horrendous but it works everywhere.