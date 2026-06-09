import gc
import sys
from ctypes import *

# -------------------------------------------------
# Helpers
# -------------------------------------------------

def read_buffer(ptr, length):
    return bytes(ptr[i] for i in range(length))


def run_test(name, fn, expect_fail=False):
    try:
        fn()
    except AssertionError as e:
        if expect_fail:
            print(f"[XFAIL] {name} (expected failure)")
            return True
        else:
            print(f"[FAIL]  {name}: {e}")
            return False
    except Exception as e:
        print(f"[ERROR] {name}: {e}")
        return False
    else:
        if expect_fail:
            print(f"[XPASS] {name} (unexpected pass)")
            return False
        print(f"[PASS]  {name}")
        return True

class cal_buffer(Structure):
    _fields_ = [
        ('len', c_size_t),
        ('buf', POINTER(c_uint8))
    ]
    _pack_ = 1

    def __init__(self, length, data: bytes|bytearray):
        self.len = c_size_t(length)
        if isinstance(data, bytearray):
            self.buf = cast((c_uint8 * length).from_buffer(data),POINTER(c_uint8))
        else:
            self.buf = cast(data, POINTER(c_uint8)) 
            
# -------------------------------------------------
# Tests
# -------------------------------------------------


def test_new_buffer_bytes_zero():
    data = bytes([0x11, 0x22, 0x00, 0x33, 0x44])
    buf = cal_buffer(len(data), data)

    gc.collect()
    out = read_buffer(buf.buf, buf.len)
    assert out == data


def test_new_buffer_bytearray_zero_copy():
    data = bytearray([1, 2, 0, 3])
    buf = cal_buffer(len(data), data)

    data[1] = 0x99
    gc.collect()

    out = read_buffer(buf.buf, buf.len)
    assert out[1] == 0x99


def test_new_buffer_lifetime_safe():
    def create():
        data = bytes([9, 8, 0, 7, 6])
        return cal_buffer(len(data), data)

    buf = create()
    gc.collect()

    out = read_buffer(buf.buf, buf.len)
    assert out == b'\x09\x08\x00\x07\x06'


# -------------------------------------------------
# Main
# -------------------------------------------------

def main():
    tests = [
        ("cal_buffer bytes with 0x00", test_new_buffer_bytes_zero, False),
        ("cal_buffer bytearray zero-copy", test_new_buffer_bytearray_zero_copy, False),
        ("cal_buffer lifetime safety", test_new_buffer_lifetime_safe, False),
    ]

    ok = True
    for name, fn, expect_fail in tests:
        ok &= run_test(name, fn, expect_fail)


if __name__ == "__main__":
    main()
