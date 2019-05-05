.. This work is licensed under a Creative Commons Attribution 4.0 International License.
.. http://creativecommons.org/licenses/by/4.0


========
Abstract
========

This document describes how to install <cran> raletive subproject, it's dependencies and required system resources.

.. contents::
   :depth: 3
   :local:

Version history
---------------------

+--------------------+--------------------+--------------------+--------------------+
| **Date**           | **Ver.**           | **Author**         | **Comment**        |
|                    |                    |                    |                    |
+--------------------+--------------------+--------------------+--------------------+
| 2019-03-19         | 0.1.0              | Weichen Ni         | First draft        |
|                    |                    |                    |                    |
+--------------------+--------------------+--------------------+--------------------+
|                    |                    |                    |                    |
|                    |                    |                    |                    |
+--------------------+--------------------+--------------------+--------------------+
|                    |                    |                    |                    |
|                    |                    |                    |                    |
|                    |                    |                    |                    |
+--------------------+--------------------+--------------------+--------------------+


Introduction
============
<INTRODUCTION TO THE SCOPE AND INTENTION OF THIS DOCUMENT AS WELL AS TO THE SYSTEM TO BE INSTALLED>


This document describes the supported software and hardware configurations for the OPNFV C-RAN project relative reference as well as providing guidelines on how to install and
configure such reference system.

Although the available installation options gives a high degree of freedom in how the system is set-up,
with what architecture, services and features, etc., not nearly all of those permutations provides
a OPNFV compliant reference architecture. Following the guidelines in this document ensures
a result that is OPNFV compliant.

The audience of this document is assumed to have good knowledge in network and Unix/Linux administration.


Preface
=======
<DESCRI
BE NEEDED PREREQUISITES, PLANNING, ETC.>

Before starting the installation of C-RAN@OPNFV, some planning must preceed.

First of all, you need to download OAI eNodeB and UE tar packeage and have them installed.
link as follow :

The eNodeB code link :
https://drive.google.com/open?id=1_BiK2vgfxdHg3hsBxvwCObcal3bVP0SD

The UE code link:
https://drive.google.com/open?id=1pwepCkk2FU6hClRL_lLnsTVYkKkGcUci


Software requirements
=====================

you will need a node of baremental envirment with two VMs.

Host OS: centos  x86_64-linux-3.10.0-51.el7.x86_64

Guest os: ubuntu 14.04.3 linux kernel>=3.19

VM model: Memory: 4GB, hard disk: 15GB, vCPU: 2


Hardware requirements
=====================

Following minimum hardware requirements must be met for installation of C-RAN@OPNFV:

Suggeted hardwrare, other capable hardware is fine.
HP DL380 PGen8, memory 64G, frequency 3.0, network card 100Mbps, hard disk 600GB



Installation manual
================================================

Based on the OAI community, CMCC contributes different version of BBU function realization. CMCC will update code when the internal legal process finished. 


I. Initial environment construction

1. Operating System : ubuntu14.04 version, linux kernel 3.19

2. In VM1, decompress the eNB.tar. In VM2, decompress the UE.tar.

eNB.tar and UE.tar can be stored anywhere you like, take /home/ as an example.

cd /home/

tar –xzvf eNB.tar

tar –xzvf UE.tar

3. Run the following command in two VMs respectively:

Open directory: cd openairinterface5g-develop-nos1/cmake_targets

Executive command (under root mode): ./build_oai -I --oaisim -x --install-system-files

Intall the lib and related tools.



II. VM1 configuration:


1. Open directory: openairinterface5g-develop-nos1/cmake_targets

2. Run the script: sh build_rcc.sh

3. Run the script: sh run_rcc.sh


III. VM2 configuration

1. Configure the VM external communication IP

(1) Open file: openairinterface5g-develop-nos1/targets/PROJECTS/GENERIC-LTE-EPC/CONF/ rru.oaisim.conf

(2) Modify the local network address, including the UE IP and local network port IP.

 RUs=(

{

local_if_name = "";//Local network port name, e.g.eth0

remote_address = ""; //UE IP

 local_address = "";// IP of local network port

……

}）

2. Code compiling:

(1) Open directory: openairinterface5g-develop-nos1/cmake_targets

(2) Run the script: sh build_rcc.sh

(3) Run the script: sh run_rcc.sh

(4) access success: In VM1, get the following log  RRCConnectionReconfigurationComplete

(5) Test case description
 

Test objection: Test the NFVI platform supporting for radio access network

Test index: Observe the downlink bandwidth of radio access network

Test scheme: Launch the Iperf function respectively in VM1 and VM2. The UE VM launches the iperf server, eNB launches the iperf client.

Test procedure:  

IP: eNB ip is 10.0.1.1, UE ip is 10.0.1.2  (If you want to modify the ip, check the openairinterface5g-develop-nos1/targets/tools/init_nas_nos1)
The destination IP is: 10.0.1.2, , the source IP is: 10.0.1.1
Under UDP mode, Iperf client sends the packets to iperf server, the test time continues 120s, the number of connection is one, the packet loss limit to 0.6%, recording the network bandwidth.

Futher test command can be found on C-RAN wiki page:
https://wiki.opnfv.org/pages/viewpage.action?pageId=24576836

