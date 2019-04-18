# usbmtp_dissector srouce
1. create new dir: wireshark\plugins\epan\usbmtp

2. copy the following files to wireshark\plugins\epan\usbmtp<br />
packet-usb-mtp.c<br />
packet-usb-mtp.h<br />
CMakeLists.txt<br />

3.
add the following dir to wireshark\CMakeLists.txt<br />
plugins/epan/usbmtp<br />

#usbmtp_dissector binary<br />
Copy usbmtp.dll to wireshark\plugins\epan and reopen wireshark, then wireshark will support usbmtp.<br />
The wireshark version need be higher than or equal to 3.0.0.
