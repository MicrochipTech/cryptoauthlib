"""
JWT: Extension to the jwt module with hardware based security
"""
# (c) 2015-2018 Microchip Technology Inc. and its subsidiaries.
#
# Subject to your compliance with these terms, you may use Microchip software
# and any derivatives exclusively with Microchip products. It is your
# responsibility to comply with third party license terms applicable to your
# use of third party software (including open source software) that may
# accompany Microchip software.
#
# THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
# EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
# WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
# PARTICULAR PURPOSE. IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT,
# SPECIAL, PUNITIVE, INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE
# OF ANY KIND WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF
# MICROCHIP HAS BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE
# FORESEEABLE. TO THE FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL
# LIABILITY ON ALL CLAIMS IN ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED
# THE AMOUNT OF FEES, IF ANY, THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR
# THIS SOFTWARE.

# pylint: disable-msg=too-few-public-methods

try:
    import hmac
    from jwt import PyJWT as Jwt
    from jwt.algorithms import ECAlgorithm, HMACAlgorithm
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes

    from .status import check_status
    from .atcab import atcab_init, atcab_release, atcab_sign, atcab_sha_hmac, atcab_nonce_rand

    class HwEcAlgorithm(ECAlgorithm):
        """
        Extended Algorithm with hardware based elliptic curve support
        """
        def __init__(self, hash_alg, slot, iface_cfg):
            super(HwEcAlgorithm, self).__init__(hash_alg)
            self._cfg = iface_cfg
            self._slot = slot

        def sign(self, msg, _):
            """
            Return a signature of the JWT with hardware ECDSA
            """
            if self._cfg is not None:
                check_status(atcab_init(self._cfg))

            digest = hashes.Hash(self.hash_alg(), backend=default_backend())
            digest.update(msg)
            digest = digest.finalize()

            signature = bytearray(64)
            check_status(atcab_sign(self._slot, digest, signature))

            if self._cfg is not None:
                check_status(atcab_release())

            return signature


    class HwHmacAlgorithm(HMACAlgorithm):
        """
        Extended Algorithm with hardware based HMAC support
        """
        def __init__(self, hash_alg, slot, iface_cfg):
            super(HwHmacAlgorithm, self).__init__(hash_alg)
            self._cfg = iface_cfg
            self._slot = slot

        def sign(self, msg, _):
            """
            Return a signature of the JWT with hardware SHA256 HMAC and stored key
            """
            if self._cfg is not None:
                check_status(atcab_init(self._cfg))

            check_status(atcab_nonce_rand(bytearray(20), bytearray(32)))

            digest = bytearray(32)
            check_status(atcab_sha_hmac(msg, len(msg), self._slot, digest, 0))

            if self._cfg is not None:
                check_status(atcab_release())

            return bytes(digest)

        def verify(self, msg, key, sig):
            """
            Verify a signature using the software HMAC module
            """
            return sig == hmac.new(key, msg, self.hash_alg).digest()


    class PyJWT(Jwt):
        """
        Extended PyJWT class from the pyjwt module
        """
        def __init__(self, slot=0, iface_cfg=None, options=None):
            super(PyJWT, self).__init__(algorithms=[], options=options)
            self.register_algorithm('ES256', HwEcAlgorithm(HwEcAlgorithm.SHA256, slot, iface_cfg))
            self.register_algorithm('HS256', HwHmacAlgorithm(HwHmacAlgorithm.SHA256, slot, iface_cfg))

    __all__ = ['PyJWT']

except ImportError:
    pass
