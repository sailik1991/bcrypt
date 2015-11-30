# bcrypt

This is a java implementation of bcrypt built with ANT build logic.  Publication for the algorithm can be found [here](http://www.openbsd.org/papers/bcrypt-paper.pdf). The encode and decode in base-64 is same as the original implementation (in [C](http://mail-index.netbsd.org/tech-crypto/2002/05/24/msg000204.html)) by Niels Provos.

The code uses different test vectors when compared to standard implementation.  The main reason for this is that all present implementations reverse the order in which salt and key are sent for encrypting ${0}^n$ inside the cost ($2^{rounds}$) iteration in the _EksBlowfishSetup_.

The code for _bcrypt_ can be found under src/impl.  A util package has the code for base-64 encoding and decoding.

If you plan to use this jar, please download the jar uploaded to git.  If you plan to build it from the source code, please use,
'''
ant jar
'''

If you wish to contribute to the code base, please make sure you test your changes before pushing:
'''
ant test
'''
