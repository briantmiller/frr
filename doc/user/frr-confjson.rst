.. _frr-confjson:

The frr-confjson tool
=====================

``frr-confjson`` converts FRR configuration between ``frr.conf`` text and JSON.

* ``to-json`` turns configuration text (by default the running configuration,
  read with ``vtysh -c "show running-config"``) into a JSON document.
* ``to-conf`` turns a JSON document into FRR configuration commands, which can
  be applied with ``vtysh -f`` or ``frr-reload.py``.

The commands it knows come from ``frr.xref``, the cross-reference file the FRR
build writes after linking the daemons.  It lists every ``DEFUN``/``DEFPY``
compiled into each daemon and module, and the CLI node(s) each one is installed
into.  ``frr.xref`` is installed in FRR's data directory
(``/usr/share/frr/frr.xref`` by default).  The node hierarchy (which command
enters which node) is taken from vtysh, which the tool links with.  Lines are parsed with FRR's own command matcher, so abbreviations, value
validation and ambiguity work exactly as in ``vtysh``.

.. note::

   ``frr.xref`` must come from the same build as ``frr-confjson``: CLI node
   numbers are compiled into the tool.

Distribution packages ship the tool and ``frr.xref`` in a separate
``frr-confjson`` package, which requires the ``frr`` package of exactly the
same version.

Usage
-----

.. program:: frr-confjson

::

   frr-confjson [options] to-json [FILE|-]
   frr-confjson [options] to-conf [FILE|-]

.. option:: -x, --xref FILE

   Command catalog to use.  Defaults to ``$FRR_XREF`` or the installed
   ``frr.xref``.

.. option:: --vtysh PATH

   vtysh binary used to read the running configuration.

.. option:: -N, --pathspace NAME

   Passed to vtysh as ``-N NAME``.

.. option:: -c, --compact

   ``to-json``: compact JSON output.

.. option:: -s, --stats

   Print catalog statistics.

.. option:: --self-test[=N]

   Check the tool against the catalog: for every configuration command of
   every node, generate ``N`` random valid lines (default 4), put each into a
   JSON document inside the commands that lead to its node, convert it back
   and verify that the same command comes out in the same place.  Also
   reports how many commands could be negated with ``"no"``.

Errors are printed to standard error as a JSON list, each with the location
(a JSON pointer such as ``/config/interface/eth0/ip/adress`` for JSON input,
``line 12`` for text input), the CLI node and a message; the exit status is
then 1.  ``to-conf`` prints nothing to standard output when any command fails.

JSON format
-----------

The JSON follows the command line: every word of a command is one level of
nesting, and the last word is the value.  A command that enters a sub-mode
(``interface``, ``router bgp``, ``address-family``...) holds the commands of
that mode.

.. code-block:: text

   hostname r1
   interface eth0
    description uplink to core
    ip address 192.0.2.1/24
   exit
   router bgp 65001
    no bgp ebgp-requires-policy
    neighbor 192.0.2.2 remote-as external
    neighbor 192.0.2.2 timers 10 30
    address-family ipv4 unicast
     network 198.51.100.0/24
     neighbor 192.0.2.2 route-map OUT out
    exit-address-family
   exit
   ip route 10.0.0.0/8 192.0.2.1
   ip route 10.0.0.0/8 192.0.2.2

is

.. code-block:: json

   {
     "config": {
       "hostname": "r1",
       "interface": {
         "eth0": {
           "description": "uplink to core",
           "ip": {"address": "192.0.2.1/24"}
         }
       },
       "router": {
         "bgp": {
           "65001": {
             "no": {"bgp": {"ebgp-requires-policy": true}},
             "neighbor": {
               "192.0.2.2": {"remote-as": "external", "timers": "10 30"}
             },
             "address-family": {
               "ipv4": {
                 "unicast": {
                   "network": "198.51.100.0/24",
                   "neighbor": {"192.0.2.2": {"route-map": {"OUT": "out"}}}
                 }
               }
             }
           }
         }
       },
       "ip": {"route": {"10.0.0.0/8": ["192.0.2.1", "192.0.2.2"]}}
     }
   }

The rules:

* A command that ends in a keyword has the value ``true``
  (``"shutdown": true``).  ``false`` leaves the command out.
* A keyword chosen from alternatives is written as a value
  (``"remote-as": "external"``, ``"route-map": {"OUT": "out"}``), and so are
  free text (``"description": "uplink to core"``), lists of values
  (``"community": "65000:1 65000:2"``) and trailing numbers
  (``"timers": "10 30"``).  Numbers can be JSON numbers.
* Several commands that differ only in their last value give a list.  A list
  may also hold objects (``["192.0.2.1", {"192.0.2.3": {"tag": 7}}]``) and
  strings with complete command lines.
* A sub-mode command without commands inside is an empty object
  (``"router": {"ospf": {}}``).  The ``exit``, ``exit-address-family``...
  commands are generated; ``exit`` cannot be used in JSON.
* A key or value may hold several words: ``"address-family ipv4 unicast"``
  as one key, or ``"timers": "10 30"``, give the same commands as the nested
  form.

When the commands are converted back, FRR's grammar decides where a sub-mode
command ends and the commands inside it begin.

Commands that start with the same words are grouped together, so the order of
commands can differ from the original text, while the commands themselves are
the same; the order of first appearance is kept.  Where FRR needs a particular
order (for example a peer group defined before its members), keep that order
in the JSON, or use a list of objects at that point, which is processed in
order.

Negated commands
^^^^^^^^^^^^^^^^

``no`` is the first word, as on the command line:

.. code-block:: json

   {"router": {"bgp": {"65001": {
     "no": {"neighbor": {"192.0.2.2": {"timers": "10 30"}}}}}}}

gives ``no neighbor 192.0.2.2 timers 10 30``.  Many ``no`` commands take
fewer arguments than the command they remove; when FRR does not accept the
negated command as written, the words at the end are dropped until it does
(``{"no": {"description": "uplink"}}`` gives ``no description``).  The command's
own keywords are never dropped, so ``no neighbor X remote-as 2`` never becomes
``no neighbor X``.  To negate a command taken from ``to-json`` output, put it
under ``"no"``.

Examples
--------

Running configuration to JSON, and back::

   frr-confjson to-json > running.json
   frr-confjson to-conf running.json > frr.conf

Apply a JSON change on top of the running configuration::

   frr-confjson to-conf change.json > change.conf && vtysh -f change.conf
