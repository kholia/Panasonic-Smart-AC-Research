Sample borrowed from https://github.com/espressif/ESP8266_RTOS_SDK URL.

$ esptool.py --chip auto image_info hello-world.bin
esptool.py v3.2-dev
WARNING: Suspicious segment 0x40210010, length 112540
WARNING: Suspicious segment 0x4022b7ac, length 28428
Image version: 1
Entry point: 402109bc
5 segments

Segment 1: len 0x1b79c load 0x40210010 file_offs 0x00000008 [IROM]
Segment 2: len 0x06f0c load 0x4022b7ac file_offs 0x0001b7ac [IROM]
Segment 3: len 0x00554 load 0x3ffe8000 file_offs 0x000226c0 [DRAM]
Segment 4: len 0x00080 load 0x40100000 file_offs 0x00022c1c [IRAM]
Segment 5: len 0x050b4 load 0x40100080 file_offs 0x00022ca4 [IRAM]
Checksum: 6c (valid
