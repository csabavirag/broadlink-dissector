# broadlink-dissector
Wireshark LUA dissector for Broadlink protocol

## Background
Everything has started with an RGBW Light bulb from Aliexpress. I configured the bulbs with their software and started using them, but since I alread had some sort of Home Assistant setup for few gadgets, I decided to search for other capabilities. Unfortunately these bulbs have never been mentioned anywhere else though.
It was fairly easy to figure out, the bulbs are using Broadlink protocol to communicate.

Then I found [broadlink-mqtt](https://github.com/eschava/broadlink-mqtt), a nice library which supports couple of Broadlink devices, but mine. Thanks to [the blog](https://blog.ipsumdomus.com/broadlink-smart-home-devices-complete-protocol-hack-bc0b4b397af1) and its very decent details of the protocol, I decided to write a Wireshark "plugin", so called dissector to see what kind of communication travels between my bulbs and the controller app in the hope to be able extend the broadlink-mqtt library to support my bulbs. And having them integrated with Home Assistant.

Wireshark supports dissectors written in C or in LUA languages. For me, LUA seemed to be easier to achieve the goal.

## Pre-requisites
Since the Broadlink protol is based on AES128-CBC encryption, we need some kind of crypto library support. I chose [luagcrypt](https://github.com/Lekensteyn/luagcrypt). To install this library I followed these steps (please note, my development was done on macOS, but the principles are the same for Windows platform too)

1. Wireshark requires **Lua 5.2**. By default I installed the most recent version from their website and unfortunately I received errors later and Wireshark was not able to load the library properly. So I followed the wiki page [Install Lua 5.2 on Mac](https://github.com/nubix-io/stuart/wiki/Install-Lua-5.2-on-a-Mac)
2. Then I added **Luarocks**
   1. Downloaded from https://luarocks.org/releases/luarocks-3.2.1.tar.gz
   1. After extraction, I run the command to install `./configure && make && make install`
3. I installed **libgcrypt** library via brew (`brew install libgcrypt`) which is the depencency of **luagcrypt**
4. And finally cloned the [luagcrypt](https://github.com/Lekensteyn/luagcrypt) library to complile
5. After the successful luagcrypt library test, I just had to move the luagcrypt.so file to /usr/local/lib/lua/5.2/

## Install
And just copied the dissector to `~/.local/lib/wireshark/plugins/broadlink.lua` on the Mac

## Usage
If everything went well, Wireshark will show the new plugin/dissector registered under About->Plugins

### Ready to capture the communication.

_**Option 1**_: I have a DD-WRT router, so it was easy to install **tcpdump** on it and use the router for remote capture. The router is the central place where the traffic goes throuh, so it will "see" the whole communication.

The DHCP table showed me, the bulb got an IP address of 192.168.1.100 (it has been configured to my home network with the Android app I received from the manufacturer!)

So I just executed 
`ssh root@192.168.1.1 tcpdump -i any -s0 -w - "host 192.168.1.100" | /Applications/Wireshark.app/Contents/MacOS/Wireshark -k -i -`

_**Option 2**_: From a rooted Android device, where the tcpdump is also available and can run the vendor's management application

`adb shell su -c tcpdump -i any -s0 -w - "host 192.168.1.100" | /Applications/Wireshark.app/Contents/MacOS/Wireshark -k -i -`

### Analyze the captured packets and use the dissector

Let's look for the AES key. The first authentication is always done with the pre-set encryption keys and the client sends the auth request (command=0x65) to the device. The device responds back to this request and in the auth response (command=0x3e9) there is the AES key which is used in any further communication. To get to these packets, filter for these packets with `broadlink.flags.command == 0x65 || broadlink.flags.command == 0x3e9`.

![image](https://user-images.githubusercontent.com/10976654/72676302-0f9efa00-3a90-11ea-833f-cd80314a32a6.png)

If the AES key is successfully extracted from the payload, set it in the protocol preferences. 

![image](https://user-images.githubusercontent.com/10976654/72676333-715f6400-3a90-11ea-9020-9dcd360b2deb.png)

With the new AES key saved, the following packets can be decrypted. Now filter the capture for command/response (`broadlink.flags.command == 0x6a || broadlink.flags.command == 0x3ee`)

![image](https://user-images.githubusercontent.com/10976654/72676510-26dee700-3a92-11ea-8ff2-31ac74a8e74b.png)

And see the response in the next packet

![image](https://user-images.githubusercontent.com/10976654/72676530-76bdae00-3a92-11ea-9f30-9f4e08231827.png)


## Conclusion
I have no other types of Broadlink device (such as RM2*, A1 etc), only these bulbs (devID: 0x60C8) so could not verify if the dissector works properly with other models, but I believe the plugin can be easily extended/modified for others.

Feel free to adjust, fork and use for your own benefit.
