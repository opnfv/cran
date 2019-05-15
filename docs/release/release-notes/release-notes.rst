.. This work is licensed under a Creative Commons Attribution 4.0 International License.
.. http://creativecommons.org/licenses/by/4.0


This document provides the release notes for <RELEASE> of <COMPONENT>.

.. contents::
   :depth: 3
   :local:


Version history
---------------

+--------------------+--------------------+--------------------+--------------------+
| **Date**           | **Ver.**           | **Author**         | **Comment**        |
|                    |                    |                    |                    |
+--------------------+--------------------+--------------------+--------------------+
| 2019-03-19         | 0.1.0              | Weichen Ni         | First draft        |
|                    |                    |                    |                    |
+--------------------+--------------------+--------------------+--------------------+
| 2019-5-16          | 0.1.1              | Weichen Ni         | First release      |
|		     |                    |                    |                    |
+--------------------+--------------------+--------------------+--------------------+
|                    |                    |                    |                    |
|                    |                    |                    |                    |
+--------------------+--------------------+--------------------+--------------------+

Important notes
===============

<STATE IMPORTANT NOTES/DEVIATIONS SINCE PREVIOUS ITERATIVE RELEASE AND OTHER IMPORTANT NOTES FOR THIS RELEASE>

<EXAMPLE>:

**Attention:** Please be aware that since LSV3 a pre-deploy script must be ran on the Fuel master -
see the OPNFV@Fuel SW installation instructions


Summary
=======

<SUMMARIZE THE RELEASE - THE CONTENT - AND OTHER IMPORTANT HIGH LEVEL PROPERTIES>

<EXAMPLE>:

Arno Fuel@OPNFV is based the OpenStack Fuel upstream project version 6.0.1,
but adds OPNFV unique components such as OpenDaylight version: Helium as well as other OPNFV unique configurations......


Release Data
============
<STATE RELEVANT RELEASE DATA/RECORDS>

<EXAMPLE>:

+--------------------------------------+--------------------------------------+
| **Project**                          | gerrit.opnfv.org/gerrit/cran         |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Repo/commit-ID**                   | E.g. genesis/adf634a0d4.....         |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Release designation**              | gerrit.opnfv.org/gerrit/cran         |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Release date**                     | 2019-05-16                           |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Purpose of the delivery**          | OPNFV H release		      |
|                                      |                                      |
+--------------------------------------+--------------------------------------+

Version change
^^^^^^^^^^^^^^^^

Module version changes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
<STATE WHAT UPSTREAM, - AS WELL AS OPNFV MODULE VERSIONS HAVE CHANGED>

<EXAMPLE>:



Document version changes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
<STATE WHAT RELATED DOCUMENTS THAT CHANGES WITH THIS RELEASE>

<EXAMPLE>:


Reason for version
^^^^^^^^^^^^^^^^^^^^
Feature additions
~~~~~~~~~~~~~~~~~~~~~~~
<STATE ADDED FEATURES BY REFERENCE TO JIRA>

<EXAMPLE>:

**JIRA BACK-LOG:**

+--------------------------------------+--------------------------------------+
| **JIRA REFERENCE**                   | **SLOGAN**                           |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| BGS-123                              | ADD OpenDaylight ml2 integration     |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| BGS-456                              | Add auto-deployment of Fuel@OPNFV    |
|                                      |                                      |
+--------------------------------------+--------------------------------------+

Bug corrections
~~~~~~~~~~~~~~~~~~~~~

**JIRA TICKETS:**

+--------------------------------------+--------------------------------------+
| **JIRA REFERENCE**                   | **SLOGAN**                           |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| BGS-888                              | Fuel doesn't deploy                  |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| BGS-999                              | Floating IP doesn't work             |
|                                      |                                      |
+--------------------------------------+--------------------------------------+

Deliverables
----------------

Software deliverables
^^^^^^^^^^^^^^^^^^^^^^^

<STATE WHAT SOFTWARE DELIVERABLES THAT ARE RELATED TO THIS VERSION, AND WHERE THOSE CAN BE RETRIEVED>

<EXAMPLE>:

Documentation deliverables
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

<STATE WHAT DOCUMENTATION DELIVERABLES THAT ARE RELATED TO THIS VERSION, AND WHERE THOSE CAN BE RETRIEVED>

<EXAMPLE>:


Known Limitations, Issues and Workarounds
=========================================

System Limitations
^^^^^^^^^^^^^^^^^^^^
<STATE ALL RELEVANT SYSTEM LIMITATIONS>

<EXAMPLE>:

**Max number of blades:**   two nodes

**Min number of blades:**   one node

**Storage:**    no specific limitation



Known issues
^^^^^^^^^^^^^^^
<STATE ALL KNOWN ISSUES WITH JIRA REFERENCE>

<EXAMPLE>:

**JIRA TICKETS:**

+--------------------------------------+--------------------------------------+
| **JIRA REFERENCE**                   | **SLOGAN**                           |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| BGS-987                              | Nova-compute process does            |
|                                      | not re-spawn when killed             |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| BGS-654                              | MOS 5.1 : neutron net-list returns   |
|                                      | "400 Bad request"                    |
|                                      |                                      |
+--------------------------------------+--------------------------------------+

Workarounds
^^^^^^^^^^^^^^^^^

<STATE ALL KNOWN WORKAROUNDS TO THE ISSUES STATED ABOVE>

<EXAMPLE>:

- In case the contact with a compute is lost - restart the compute host
- In case the disk is full on a controller - delete all files in /tmp

Test Result
===========
<STATE THE QA COVERAGE AND RESULTS>

<EXAMPLE>:

Fuel@OPNFV Arno RC2 has undergone QA test runs with the following results:

+--------------------------------------+--------------------------------------+
| **TEST-SUITE**                       | **Results:**                         |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| Tempest test suite 123               | Following tests failed:              |
|                                      |                                      |
|                                      | 1. Image resizing....                |
|                                      |                                      |
|                                      | 2. Heat deploy....                   |
+--------------------------------------+--------------------------------------+
| Robot test suite 456                 | Following tests failed:              |
|                                      |                                      |
|                                      | 1.......                             |
|                                      |                                      |
|                                      | 2.......                             |
+--------------------------------------+--------------------------------------+

References
==========
<STATE RELEVANT REFERENCES FOR THIS RELEASE/VERSION>

<EXAMPLE>:

For more information on the OPNFV Danube release, please see:

http://opnfv.org/danube
