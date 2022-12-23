<!--
.\" Copyright (C) 2020 VirtualSquare. Project Leader: Renzo Davoli
.\"
.\" This is free documentation; you can redistribute it and/or
.\" modify it under the terms of the GNU General Public License,
.\" as published by the Free Software Foundation, either version 2
.\" of the License, or (at your option) any later version.
.\"
.\" The GNU General Public License's references to "object code"
.\" and "executables" are to be interpreted as the output of any
.\" document formatting or typesetting system, including
.\" intermediate and printed output.
.\"
.\" This manual is distributed in the hope that it will be useful,
.\" but WITHOUT ANY WARRANTY; without even the implied warranty of
.\" MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
.\" GNU General Public License for more details.
.\"
.\" You should have received a copy of the GNU General Public
.\" License along with this manual; if not, write to the Free
.\" Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
.\" MA 02110-1301 USA.
.\"
-->
# NAME 

`libvdeplug_vlan` -- vdeplug nested module: VLAN (802.1Q)

# SYNOPSIS
libvdeplug_vlan.so

# DESCRIPTION

This is a libvdeplug module implementing VLANs (IEEE 802.1Q).

With this plugin VLANs are implemented in a distributed fashion. The tagging (and
untagging) of the packets is done, not by the switch, but by the plugin
(attached to the VM).

This  module of libvdeplug4 can be used in any program supporting vde like
`vde_plug`, `vdens`, `kvm`, `qemu`, `user-mode-linux` and `virtualbox`.

The vde_plug_url syntax of this module is the following:

  `vlan://`[*untagged_vlan*][`[`OPTION[`/`OPTION]...`]`]`{`*vde nested url*`}`

`untagged_vlan` is the number of the VLAN to which the virtual machine is connected in untagged mode. The traffic
on this VLAN will be seen by the VM as untagged.  If omitted the default value is 0,  an  invalid  VLAN  number
meaning that the VM is not connected to any VLAN in untagged mode.

# OPTIONS

  `u`, `untag`
: Untagged traffic on the network will be seen by the VM as traffic tagged with this tag.
: The default value is 0, an invalid VLAN number meaning untagged traffic will not
: be tagged.

: If we are sure that the traffic going by over the virtual link will only be tagged,
: untag argument is useless.
: If untagged traffic is expected and untag is 0, \fIuntagged_vlan\fR should be 0 too;
: otherwise there would not be a method to tell untagged traffic from traffic tagged for the
: untagged VLAN, and errors during send or receive may occur.

  `t`, `tag`
: A string used to specify the VLANs to which the VM is connected in tagged mode.
: The string is made up of a list of tokens separated by ":" or ".". These tokens
: can have two forms:

  ` `
: \(1\) single vlan tag number meaning that the VM is connected to that VLAN in tagged mode.

  ` `
: \(2\) Two numbers separated by "-", meaning that the tagged packets sent out by
the VM with the first number as VLAN tag are remapped on the VLAN with the second
tag number and the packets received by the VM on the VLAN with the second number
are remapped on the VLAN with the first number.

  `x`, `trunk`
: A boolean argument to be used only if the connection uses trunking. If used the VM will
: be able to send and receive packets from VLANs not listed in the tag string.

  `q`, `qinq`, `ad`
: Use the ethernet type 0x88A8 for the double tagging protool 802.1ad (also known as QinQ).

# EXAMPLES

```
  vlan://3{tap://mytap}
```

  The VM is connected to vlan 3 and receives only traffic from here.

```
  vlan://3[untag=4/trunk/tag=10:11-12:12-11]{vde:///tmp/myswitch}
```

  The VM is connected to vlan 3 in untagged mode and receive untagged traffic with
  vlan tag 4. The vlan also receives traffic from VLANs 10, 11 and 12. VLANs 11 and
  12 are switched.

```
  vdens vlan://4{vlan://5/qinq{vxvde://234.1.2.3}}
```

  This example uses 802.1ad: the VDE client is connected to the VLAN 4 of the QinQ VLAN 5.

# NOTICE

Virtual  Distributed  Ethernet  is not related in any way with www.vde.com ("Verband der Elektrotechnik, Elektronik
und Informationstechnik" i.e. the German "Association for Electrical, Electronic & Information Technologies").

# SEE ALSO
`vde_plug`(1)

