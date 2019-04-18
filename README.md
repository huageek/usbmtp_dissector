# usbmtp_dissector srouce
1. create new dir: wireshark\plugins\epan\usbmtp

2. copy the following files to wireshark\plugins\epan\usbmtp
packet-usb-mtp.c
packet-usb-mtp.h
CMakeLists.txt

3.
add the following dir to wireshark\CMakeLists.txt
plugins/epan/usbmtp

#usbmtp_dissector binary
Copy usbmtp.dll to wireshark\plugins\epan and reopen wireshark, then wireshark will support usbmtp.
The wireshark version need be higher than or equal to 3.0.0.
