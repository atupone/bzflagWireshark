# bzflagWireshark
A plugin for wireshark. Decode bzflag protocol

It is based on wireshark 2.0

To install it on Linux get the package for wireshark 2.0 and install it.

Get the wireshark source and put in a directory.

Put the content of this plugin in a directory called bzflag under the plugin directory in the wireshark source tree.

    Edit the configure.ac and add the line
plugins/bzflag/Makefile
    just before the similar line
plugins/docsis/Makefile

    Edit the Makefile.am in the plugin directory and add the line 
bzflag \
    just before the line
docsis \

Go the wireshark source upper directory and run the autogen.sh command

now go on the plugins/bazflag directory and do
make

the bzflag.so library will be generated. Move that to where wireshark is looking for plugin.
You normally need superuser privilege to do that.
Here I do :

# cp plugin/bzflag/.libs/bzflag.so /usr/lib/wireshark/plugins/2.0.4

Now, when you start wireshark it will automatically detect if there is a bzflag protocol, and decode it accordingly
