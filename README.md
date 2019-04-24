# MapReduceHomomorphic

This project is the research project for UTK CS560 course project.

This project implements homomorphic Paillier encryption using Map-Reduce framework based on Hadoop. The source code seems complex because all the python files need to be executed in cluster envrionment, and the coder does not have the privilege to install phe library on the cluster. All the codes between 'begin of phe library' and 'end of phe library' are borrowed from python phe library (https://github.com/n1analytics/python-paillier) with necessary modification. For user who owns the privilege to install library can just import library without this mess.

By the way, Hadoop is also necessary to execute the python files.
