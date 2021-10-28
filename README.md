# Wireshark protocol decoder for FIDO(U2F) and FIDO2(WebAuthn) over USB HID

This is an improved and corrected version of the Wireshark dissector created by by GitHub user z4yx, original version https://gist.github.com/z4yx/218116240e2759759b239d16fed787ca

# Installation 

Copy the lua file into your user Wireshark plugins directory.
On Windows for example `%APPDATA%\Wireshark\plugins`

Fido WebAuthn authenticators use the USB HID protocol, so Wireshark can't distinguish if an USB device is a mouse, keyboard or a FIDO2 authenticator. Therefore you have to add the USB PID/VID of your used FIDO 2 authenticator at the end of the lua dissector file so Wireshark knows to which packets the dissector should be applied to.

# References

* [FIDO alliance CTAP2 documentation](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.pdf)