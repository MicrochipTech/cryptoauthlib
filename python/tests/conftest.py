# content of conftest.py
import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--with-lib", action="store_true", help="Run Tests against a library instance"
    )
    parser.addoption(
        "--with-device", action="store_true", help="Run Tests that require a real device"
    )


@pytest.fixture
def test_init_with_lib(request):
    """
    If a test requires a compiled library skip it if this option is not specified
    """
    if not request.config.getoption("--with-lib"):
        pytest.skip('--with-lib option was not specified')


@pytest.fixture
def test_init_with_device(request):
    """
    If a test requires a real device skip the test if this option is not specified
    """
    if not request.config.getoption("--with-device"):
        pytest.skip('--with-device option was not specified')


def pytest_configure(config):
    import sys
    sys._called_from_test = True


def pytest_unconfigure(config):
    import sys
    del sys._called_from_test
