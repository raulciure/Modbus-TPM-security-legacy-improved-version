from src.modbus_tpm_security.security import AES_encrypt_and_digest, AES_decrypt_and_verify, derivate_session_salt
from types import SimpleNamespace
from random import randbytes, randrange

TIMESTAMP_OPERATION = True


if TIMESTAMP_OPERATION is True:
    args = SimpleNamespace(use_seq_num_replay_resistance=False, disable_replay_resistance=False, set_timestamp_tolerance=None)

    msg = b"Hello there!"
    key = b"vfbxEsPCj1g46wlNQSlUdEUe7U4nFb59"

    print("msg = ", msg)
    print("key = ", key)

    enc_msg = AES_encrypt_and_digest(args, key, msg)

    print("enc_msg_size = ", len(enc_msg))

    print("enc_msg = ", enc_msg.hex(' '))

    dec_msg = AES_decrypt_and_verify(args, key, enc_msg)

    print("dec_msg = ", dec_msg)

    print("\n------- RANDOM MESSAGE TEST FOLLOWS -------\n")

    for i in range(20):
        msg = randrange(1, 10000)
        print("msg = ", msg)

        enc_msg = AES_encrypt_and_digest(args, key, msg.to_bytes(4))

        print("enc_msg_size = ", len(enc_msg))
        print("enc_msg = ", enc_msg.hex(' '))

        dec_msg = AES_decrypt_and_verify(args, key, enc_msg)
        print("dec_msg = ", int.from_bytes(dec_msg))

        print("\n----------------------------------------------------\n")

else:
    args = SimpleNamespace(use_seq_num_replay_resistance=True, disable_replay_resistance=False)
    session_salt = derivate_session_salt(randbytes(32))
    seq_num = SimpleNamespace(value=0)
    expected_seq_num = SimpleNamespace(value=0)

    msg = b"Hello there!"
    key = b"vfbxEsPCj1g46wlNQSlUdEUe7U4nFb59"

    print("msg = ", msg)
    print("key = ", key)
    print("session_salt = ", session_salt.hex(' '))

    enc_msg = AES_encrypt_and_digest(args, key, msg, session_salt, seq_num)

    print("enc_msg_size = ", len(enc_msg))

    print("enc_msg = ", enc_msg.hex(' '))

    dec_msg = AES_decrypt_and_verify(args, key, enc_msg, session_salt, expected_seq_num)

    print("dec_msg = ", dec_msg)

    print("\n------- RANDOM MESSAGE TEST FOLLOWS -------\n")

    for i in range(20):
        msg = randrange(1, 10000)
        print("msg = ", msg)

        enc_msg = AES_encrypt_and_digest(args, key, msg.to_bytes(4), session_salt, seq_num)

        print("enc_msg_size = ", len(enc_msg))
        print("enc_msg = ", enc_msg.hex(' '))

        dec_msg = AES_decrypt_and_verify(args, key, enc_msg, session_salt, expected_seq_num)
        print("dec_msg = ", int.from_bytes(dec_msg))

        print("\n----------------------------------------------------\n")