citadel
=======

Citadel is a replacement for dos-deflate (ddos.sh) implemented in Perl.

To use, you can either build and then install the RPM via citadel.spec, or use the one I prebuilt:

yum localinstall http://ssullivan.org/citadel-0.1.2-1.noarch.rpm

If you are on a non-RPM platform, just run the 'install/uninstall' scripts as needed from the root of this repository.

What citadel doesn't do:

1.) No IPv6 support
2.) No nftable support.
