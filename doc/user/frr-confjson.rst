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
into.  ``frr.xref`` is installed in FRR's data directory (``/usr/share/frr/frr.xref`` by default).  The node hierarchy
(which command enters which node) is taken from vtysh, which the tool links
with.  Lines are parsed with FRR's own command matcher, so abbreviations, value
validation and ambiguity work exactly as in ``vtysh``.

.. note::

   ``frr.xref`` must come from the same build as ``frr-confjson``: CLI node
   numbers are compiled into the tool.

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

.. option:: -l, --lines

   ``to-json``: emit plain configuration lines instead of ``cmd``/``params``
   objects (the block structure is kept).

.. option:: -c, --compact

   ``to-json``: compact JSON output.

.. option:: -s, --stats

   Print catalog statistics.

.. option:: --self-test[=N]

   Check the tool against the catalog: for every configuration command of
   every node, generate ``N`` random valid lines (default 4), convert each to
   JSON and back, and verify the same command with the same parameters comes
   out.  Also reports how many positive statements could be negated with
   ``"no": true``.

Errors are printed to standard error as a JSON list, each with the location
(``/config/3/config/0`` for JSON input, ``line 12`` for text input), the CLI
node and a message; the exit status is then 1.  ``to-conf`` prints nothing to
standard output when any statement fails.

JSON format
-----------

.. code-block:: json

   {
     "config": [
       {"cmd": "hostname", "params": {"hostname": "r1"}},
       {"cmd": "interface", "params": {"ifname": "eth0"}, "config": [
         {"cmd": "ip address", "params": {"address": "192.0.2.1/24"}}
       ]},
       {"cmd": "router bgp", "params": {"instasn": 65001}, "config": [
         {"cmd": "bgp ebgp-requires-policy", "no": true},
         {"cmd": "neighbor remote-as",
          "params": {"neighbor": "192.0.2.2", "remote_as": "external"}},
         {"cmd": "address-family ipv4 unicast", "config": [
           {"cmd": "network", "params": {"prefix": "198.51.100.0/24"}}
         ]}
       ]},
       "ip route 0.0.0.0/0 192.0.2.254"
     ]
   }

A statement is either a string, which is a literal configuration line checked
against the node it appears in, or an object:

``cmd``
   The command's signature: its fixed keywords, without a leading ``no``
   (``neighbor remote-as``, ``ip route``).  It may also be a complete line.
``params``
   Parameter values.  Names are the command's ``DEFPY`` variable names where it
   has them, otherwise the keyword in front of the value (``router-id A.B.C.D``
   gives ``router_id``).  Optional keywords are booleans (``"unicast": true``);
   a keyword choice takes the keyword (``<deny|permit>$action`` gives
   ``"action": "permit"``); integer ranges and plain AS numbers are numbers;
   ``WORD...`` takes a string or a list.
``no``
   ``true`` for the negated command (see below).
``id``
   The command's name in ``frr.xref``.  ``to-json`` adds it only when ``cmd``
   and ``params`` alone would select a different command.
``config``
   Statements inside the node this command enters.  Indentation and the
   matching ``exit``/``exit-address-family``/``exit-vrf``... are generated.

Negated commands
^^^^^^^^^^^^^^^^

``"no": true`` produces the ``no`` form of a statement.  The tool uses the
command's ``[no] ...`` variant or its separate ``no ...`` command, whichever
exists.  Many ``no`` commands take fewer arguments than the command they
remove.  When the negated command has no use for some of the given
parameters, those parameters are dropped:

.. code-block:: json

   {"cmd": "description", "no": true, "params": {"line": "uplink"}}

gives ``no description``.  A literal line with ``"no": true`` is handled the
same way: trailing words are removed until FRR accepts the line.  So a
statement copied from ``to-json`` output can be negated by adding
``"no": true``.

Examples
--------

Running configuration to JSON, and back::

   frr-confjson to-json > running.json
   frr-confjson to-conf running.json > frr.conf

Apply a JSON change on top of the running configuration::

   frr-confjson to-conf change.json > change.conf && vtysh -f change.conf
