from src.modbus_tpm_security.security import AES_encrypt_and_digest, AES_decrypt_and_verify, derivate_session_salt
from types import SimpleNamespace
from random import randbytes, randrange

TIMESTAMP_OPERATION = False


if TIMESTAMP_OPERATION is True:
    args = SimpleNamespace(use_seq_num_replay_resistance=False, disable_replay_resistance=False, set_timestamp_tolerance=None)

    msg = b"Hello there!"
    key = b"vfbxEsPCj1g46wlNQSlUdEUe7U4nFb59"

    rekey_flag = 0
    dh_public_key = randbytes(32)

    print("msg = ", msg)
    print("key = ", key)
    print("rekey_flag = ", rekey_flag)
    print("dh_public_key = ", dh_public_key)

    enc_msg = AES_encrypt_and_digest(args, key, msg, rekey_flag, dh_public_key)

    print("enc_msg_size = ", len(enc_msg))

    print("enc_msg = ", enc_msg.hex(' '))

    auth_recv_rekey_flag, dec_msg, recv_dh_public_key = AES_decrypt_and_verify(args, key, enc_msg) 
    print("auth_recv_rekey_flag = ", auth_recv_rekey_flag)
    print("dec_msg = ", dec_msg)
    print("recv_dh_public_key = ", recv_dh_public_key)

    print("\n------- RANDOM MESSAGE TEST FOLLOWS -------\n")

    for i in range(20):
        msg = randrange(1, 10000)
        print("msg = ", msg)

        enc_msg = AES_encrypt_and_digest(args, key, msg.to_bytes(4), rekey_flag, b'')

        print("enc_msg_size = ", len(enc_msg))
        print("enc_msg = ", enc_msg.hex(' '))

        auth_recv_rekey_flag, dec_msg, recv_dh_public_key = AES_decrypt_and_verify(args, key, enc_msg)
        print("auth_recv_rekey_flag = ", auth_recv_rekey_flag)
        print("dec_msg = ", int.from_bytes(dec_msg))
        print("recv_dh_public_key = ", recv_dh_public_key)

        print("\n----------------------------------------------------\n")

else:
    args = SimpleNamespace(use_seq_num_replay_resistance=True, disable_replay_resistance=False)
    session_salt = derivate_session_salt(randbytes(32))
    seq_num = SimpleNamespace(value=0)
    expected_seq_num = SimpleNamespace(value=0)

    msg = b"Hello there!"
    key = b"vfbxEsPCj1g46wlNQSlUdEUe7U4nFb59"

    rekey_flag = 0
    dh_public_key = randbytes(32)

    print("msg = ", msg)
    print("key = ", key)
    print("session_salt = ", session_salt.hex(' '))
    print("rekey_flag = ", rekey_flag)
    print("dh_public_key = ", dh_public_key)

    enc_msg = AES_encrypt_and_digest(args, key, msg, rekey_flag, dh_public_key, session_salt, seq_num)

    print("enc_msg_size = ", len(enc_msg))

    print("enc_msg = ", enc_msg.hex(' '))

    auth_recv_rekey_flag, dec_msg, recv_dh_public_key = AES_decrypt_and_verify(args, key, enc_msg, session_salt, expected_seq_num)
    print("auth_recv_rekey_flag = ", auth_recv_rekey_flag)
    print("dec_msg = ", dec_msg)
    print("recv_dh_public_key = ", recv_dh_public_key)

    print("\n------- RANDOM MESSAGE TEST FOLLOWS -------\n")

    for i in range(20):
        msg = randrange(1, 10000)
        print("msg = ", msg)

        enc_msg = AES_encrypt_and_digest(args, key, msg.to_bytes(4), rekey_flag, b'', session_salt, seq_num)

        print("enc_msg_size = ", len(enc_msg))
        print("enc_msg = ", enc_msg.hex(' '))

        auth_recv_rekey_flag, dec_msg, recv_dh_public_key = AES_decrypt_and_verify(args, key, enc_msg, session_salt, expected_seq_num)
        print("auth_recv_rekey_flag = ", auth_recv_rekey_flag)
        print("dec_msg = ", int.from_bytes(dec_msg))
        print("recv_dh_public_key = ", recv_dh_public_key)

        print("\n----------------------------------------------------\n")