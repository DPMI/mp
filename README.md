DPMI Measurement Point
======================

[![Build Status](https://travis-ci.org/DPMI/mp.svg?branch=master)](https://travis-ci.org/DPMI/mp)

Install
-------

    autoreconf -si # if from git repo
    ./configure [--with-dag=PREFIX] [--with-pcap] [--without-raw]
    make
    make install

Running locally
---------------

    mp --local -v -i pcapeth0 -s eth1 --caplen 96 -o 01::10

Where "pcapeth0" is the device to capture on (eth0, using pcap) and "eth1" is the output interface to broadcast on. `01::10` is the DPMI output address.

    mp --local -v- i pcapeth0 --caplen 96 -o myfile.cap

Same as above but saving to `myfile.cap` instead of broadcasting.

Running with MArCd
------------------

    mp -v -i dag0 -s eth0

Where "dag0" is the device to capture on (dag0, using DAG-card) and "eth0" is the interface MArCd is running on.
