# vdeplug\_vlan
802.1q (vlan) nested plugin for vdeplug4

This libvdeplug plugin module implements VLANs.

This module of libvdeplug4 can be used in any program supporting VDE like vde\_plug, vdens, kvm, qemu, user-mode-linux and virtualbox.

## install vdeplug\_vlan

Requirements: [vdeplug4](https://github.com/rd235/vdeplug4).

vdeplug\_vlan uses cmake, so the standard procedure to build and install
this vdeplug plugin module is the following:

```sh
$ mkdir build
$ cd build
$ cmake ..
$ make
$ sudo make install
```

## usage examples (tutorial)

The following examples are UVDELs (Unified VDE Locator) to be used with programs
supporting vde as specified by the syntax of those programs.

### Connect the VM to VLAN 3
```vlan://3{tap://mytap}```

### Connect the VM to VLAN 3 and other options
```vlan://3[untag=4/trunk/tag=10:11-12:12-11]{vde:///tmp/myswitch}```

## Create a vde namespace (in VLAN 3) connected to a switch
```vdens vlan://3{vde:///tmp/myswitch}```

See the man page (libvdeplug\_vlan) for more information.
