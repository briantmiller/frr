************
FRR-CONFJSON
************

.. include:: defines.rst
.. |PROGRAM| replace:: frr-confjson

SYNOPSIS
========
|PROGRAM| [ *options* ] to-json [ *FILE* | - ]

|PROGRAM| [ *options* ] to-conf [ *FILE* | - ]

DESCRIPTION
===========
|PROGRAM| converts FRR configuration between frr.conf text and JSON.

**to-json** converts configuration text to a JSON document.  Without *FILE*,
the running configuration is read with ``vtysh -c "show running-config"``.

**to-conf** converts a JSON document to FRR configuration commands, which can
be applied with ``vtysh -f``.  Statements with ``"no": true`` produce the
negated command.

The commands it knows are read from frr.xref, the command catalog produced by
the FRR build.  frr.xref must come from the same build as |PROGRAM|.

OPTIONS
=======
.. option:: -x, --xref FILE

   Command catalog to use.  Defaults to ``$FRR_XREF``, else
   /usr/share/frr/frr.xref.

.. option:: --vtysh PATH

   vtysh binary used to read the running configuration.

.. option:: -N, --pathspace NAME

   Passed to vtysh as ``-N NAME``.

.. option:: -l, --lines

   to-json: emit plain configuration lines instead of cmd/params objects.

.. option:: -c, --compact

   to-json: compact JSON output.

.. option:: -s, --stats

   Print catalog statistics to standard error.

.. option:: --self-test[=N]

   Round-trip N random valid lines of every configuration command through
   JSON and report the result.

.. option:: -h, --help

   Display usage information.

EXIT STATUS
===========
0 on success.  1 if any line or statement was rejected; the errors are
printed to standard error as a JSON list, and to-conf prints no commands.
2 on usage errors or when the input or catalog cannot be read.

FILES
=====
/usr/share/frr/frr.xref
   The command catalog.

SEE ALSO
========
vtysh(1)

The "frr-confjson" chapter of the FRR user guide describes the JSON format.

.. include:: epilogue.rst
