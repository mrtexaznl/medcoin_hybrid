medcoin_hybrid
==============

Python module extension for HybridScryptHash256 Proof of Work algorithm


Requirements:
-------------------------
In order to build and install the medcoin_hybrid module that includes the HybridScryptHash256 proof of work code that MediterraneanCoin uses for hashes, do the following:

Linux:

note: if running on a fresh Ubuntu machine, you will need also the following packages:
sudo aptitude install build-essential python2.7-dev

    cd medcoin_hybrid
    sudo python setup.py install


Windows (mingw):
* Install MinGW: http://www.mingw.org/wiki/Getting_Started
* Install Python 2.7: http://www.python.org/getit/

In bash type this:

    cd medcoin_hybrid
    C:\Python27\python.exe setup.py build --compile=mingw32 install

Windows (microsoft visual c++)
* Open visual studio console

In bash type this:

    SET VS90COMNTOOLS=%VS110COMNTOOLS%	           # For visual c++ 2012
    SET VS90COMNTOOLS=%VS100COMNTOOLS%             # For visual c++ 2010
    cd medcoin_hybrid
    C:\Python27\python.exe setup.py build --compile=mingw32 install
