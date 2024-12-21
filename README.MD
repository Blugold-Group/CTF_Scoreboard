# Blugold Group Website

This website is the website for the Blugold Group, the cybersecurity club of the University of Wisconsin - Eau Claire.

It is not meant to be hosted on the open web, but rather on the cybersecurity lab network. Its hosted on the open web over the winterim 2024-2025 to provide access for members to a Winterim CTF

As we are a technical club, we try to make the documentation for the server as clear and comprehensive as possible to lower the barrier for members to dig into the code with as little tachnical experience as possible. As such, this documentation file aims to be a comprehensive guide to every moving part of the server.

This guide is still a work in progress

## Architecture

The server is written in python to allow a lower barrier of entry to developing it. By design, it should allow people to develop it long after I'm gone. That's why I'm trying to write this guide to be as comprehensive as possible.

### Routes

### Badges

To change: `UPDATE users SET tags = 'Exec,Master Locksmith' WHERE username = 'adminn';`

Has to be a comma seperated list, no spaces

Add new badges in the `/about/badges` page and the css of `/members`

### Database

## Hall of History

If you add on to this codebase, please add your name below

This server was created by Jack Hagen (the founder of the club) over a weekend in October 2024

### Historical Notes

The CLEAS was originally meant to authenticate id tags unique to each club member, allowing us to see who unlocked what when. The lock permissions were meant to be tied to user accounts on this server, so any mention of locks in the code references that. Ultimately we just used a basic nfc lock which uses one nfc password which was copied to several tags to be shared by all members.

## Server Setup

At the time of writing, I am currently setting up the server to run on a raspberry pi, using Cloudflare to tunnel to the open internet. I don't know how you will host this in the future, but as of now this file will hold documentation for how the server is setup as well as the programming

For some reason when running from cron after reboots, setting up a Cloudflare tunnel and SSH tunnel fail because they can't reach the network, I'm assuming that network services just haven't booted by that point, so delaying them 10 seconds did the trick  