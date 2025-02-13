### Migrating to v3.7.6 to v3.7.7

atcacert
===============================================================================

atcacert API Migration
-------------------------------------------------------------------------------

This release adds support for TA Compressed certs in atcacert module.

In order to support these, especially on resource constrained device,
the atcacert APIs have been modified to accept array inputs as a new structure,
`cal_buffer` which allows multipart buffers to be used to provide data to these
APIs. This makes for a substantial number of changes to function signatures

#### Using the `cal_buffer` structure

This structure for most circumstances simply ensures that the length of the data
is included with the buffer provided. There are two convienence macros provided
for initialization: `CAL_BUF_INIT` & `CAL_BUF_INIT_LINK`. The later macro is
only used when multipart buffers are enabled (rare). A simple example of their
usage is as follows:

    uint8_t signer_ca_public_key[64] = { 0 };
    cal_buffer signer_ca_public_key_buf = CAL_BUF_INIT(sizeof(signer_ca_public_key), signer_ca_public_key);

    status = atcacert_read_cert(&cert_def, &signer_ca_public_key_buf, cert, &cert_size);


#### Function Migration

| v3.7.6                                        | v3.7.7                                        | Parameter Changes                         |
| --------------------------------------------- | --------------------------------------------- | ----------------------------------------- |
| atcacert_get_response                         | [atcacert_get_response]                       | Buffers                                   |
| atcacert_read_cert                            | [atcacert_read_cert]                          | Public key Buffer                         |
| atcacert_read_cert_ext                        | [atcacert_read_cert_ext]                      | Public key Buffer                         |
| atcacert_merge_device_loc                     | [atcacert_merge_device_loc]                   | Added device context                      |
| atcacert_cert_build_start                     | [atcacert_cert_build_start]                   | Buffers                                   |
| atcacert_set_subj_public_key                  | [atcacert_set_subj_public_key]                | Public key Buffer                         |
| atcacert_set_signature                        | [atcacert_set_signature]                      | Signature Buffer                          |
| atcacert_get_signature                        | [atcacert_get_signature]                      | Signature Buffer                          |
| atcacert_generate_sn                          | [atcacert_generate_sn]                        | Public key Buffer                         |
| atcacert_set_auth_key_id                      | [atcacert_set_auth_key_id]                    | Public key Buffer                         |
| atcacert_get_tbs_digest                       | [atcacert_get_tbs_digest]                     | Digest key Buffer                         |
| atcacert_get_key_id                           | [atcacert_get_key_id]                         | Public key Buffer                         |
| atcacert_der_enc_ecdsa_sig_value              | [atcacert_der_enc_ecdsa_sig_value]            | Signature Buffer                          |
| atcacert_der_dec_ecdsa_sig_value              | [atcacert_der_dec_ecdsa_sig_value]            | Signature Buffer                          |
| atcacert_verify_cert_hw                       | [atcacert_verify_cert_hw]                     | Public key Buffer                         |
| atcacert_gen_challenge_hw                     | [atcacert_gen_challenge_hw]                   | Buffers                                   |
| atcacert_verify_response_hw                   | [atcacert_verify_response_hw]                 | Buffers                                   |
| atcacert_gen_challenge_sw                     | [atcacert_gen_challenge_sw]                   | Buffers                                   |
| atcacert_verify_cert_sw                       | [atcacert_verify_cert_sw]                     | Public key Buffer                         |
| atcacert_verify_response_sw                   | [atcacert_verify_response_sw]                 | Buffers                                   |



