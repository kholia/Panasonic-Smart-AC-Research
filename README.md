### Panasonic-AC-Research

While trying to setup my Panasonic Smart AC using the `Panasonic MirAIe` app, I
ran into the `AONB` error code. After clicking on the discovered AC device, the
app immediately showed this error code, and asked me to contact `Customer Care`.

After receiving no support from the `Panasonic Customer Care (app.support@miraie.in)`,
I decided to debug, and reverse-engineer the app to get around this error code.

ATTENTION: This educational reverse engineering work was carried for enabling
'software interoperability' of `Panasonic ACs` with Linux (+ other free
systems). Any commercial/pecuniary usage is STRICTLY FORBIDDEN and is at your
own risk!

Results: We are now able to control the AC (`Panasonic CS-CU-WU18WKYXF`) from a
Linux computer over MQTT! We were also able to grab the `ESP8266 Controller`
firmware file for further analysis, and fun.

PS: `AONB` probably means `Already Onboarded`.

![sample-pic](./sample-pic.jpg)

Image Credit: Google Images.


#### Useful Commands

```
frida -l frida_ssl_root_bypass_combo.js -U -f com.panasonic.in.miraie --no-pause
```

```
mitmproxy --set ssl_insecure -s mitmproxy_faker_plugin.py
```


#### Usage

```
pip3 install -r requirements.txt  # once

python3 onboarding-1.py  # once

python3 mqtt-example.py  # turns on the ac and sets the temperature
```


#### Firmware Notes

```
$ esptool.py --chip esp8266 image_info ac.ota.bin
esptool.py v3.2-dev
WARNING: Suspicious segment 0x40210010, length 437988
Image version: 1
Entry point: 4021c734
4 segments

Segment 1: len 0x6aee4 load 0x40210010 file_offs 0x00000008 [IROM]
Segment 2: len 0x009f0 load 0x3ffe8000 file_offs 0x0006aef4 [DRAM]
Segment 3: len 0x00190 load 0x3ffe89f0 file_offs 0x0006b8ec [DRAM]
Segment 4: len 0x065bc load 0x40100000 file_offs 0x0006ba84 [IRAM]
Checksum: 78 (valid)
```


#### References

- https://boredpentester.com/reversing-esp8266-firmware-part-1/

- https://github.com/espressif/ESP8266_RTOS_SDK (firmware uses this)

- https://github.com/Ebiroll/ghidra-xtensa

- https://github.com/yath/ghidra-xtensa

- https://github.com/crankyoldgit/IRremoteESP8266 (neat!)

- https://github.com/zayfod/esp-bin2elf (not used, buggy?)
