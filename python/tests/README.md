# Python CryptoAuthLib Module Testing

## Introduction
These tests are designed to only test the python interface to the library and
are not designed to test the library itself which is covered by the main 
cryptoauthlib tests

### Running
The best way to run the test suite is to use [tox](https://tox.readthedocs.io/en/latest/)
which can be easily installed with pip:

```
$ pip install tox
```

From the python folder:

```
:~/cryptoauthlib/python $ tox
```

It is possible to directly run tests but requires more setup

1) Install pytest

```
$ pip install pytest
```

2) Modify the PYTHONPATH environment variable

Windows:
```
cryptoauthlib/python> set PYTHONPATH=<path_to>/cryptoauthlib/python
```

Linux:
```
$ export PYTHONPATH=${PYTHONPATH}:<path_to>/cryptoauthlib/python
```

3) Run the tests
```
$ pytest -vv
```

### Test options

There are additional options that can be invoked with the tests that define
what tests will be run

1) --with-lib will attempt to run tests against the compiled c library.
These tests are good for detecting possible platform incompabilities between
the C compiler and the expectations of python

2) --with-device will attempt to invoke some tests with a real attached device
These tests are restricted to only the minimum required to verify the python to
library connectivity and are only meant to detect situations can can not be
determined from the library tests alone.


