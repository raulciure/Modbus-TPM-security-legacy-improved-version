from src.modbus_tpm_security.security import AES_encrypt_and_digest, AES_decrypt_and_verify, derivate_session_salt
from types import SimpleNamespace
from random import randbytes, randrange
from src.modbus_tpm_security.perf_test import latency_test


TIMESTAMP_OPERATION = True
MSG_SIZE = 12
TEST_RUNS = 20000

msg = randbytes(MSG_SIZE)
key = randbytes(32)
rekey_flag = 0
dh_public_key = b''

if TIMESTAMP_OPERATION is True:
    args = SimpleNamespace(use_seq_num_replay_resistance=False, disable_replay_resistance=False, set_timestamp_tolerance=None)
else:
    args = SimpleNamespace(use_seq_num_replay_resistance=True, disable_replay_resistance=False)

session_salt = derivate_session_salt(randbytes(32))
seq_num = SimpleNamespace(value=0)
expected_seq_num = SimpleNamespace(value=0)

for i in range(TEST_RUNS):
    msg = randbytes(MSG_SIZE)

    start_time = latency_test.perf_counter()
    enc_msg = AES_encrypt_and_digest(args, key, msg, rekey_flag, b'', session_salt, seq_num)
    stop_time = latency_test.perf_counter()
    [latency_test.encrypt_average_latency, latency_test.encrypt_average_counter] = latency_test.add_to_average(latency_test.encrypt_average_latency, latency_test.encrypt_average_counter, stop_time - start_time)

    start_time = latency_test.perf_counter()
    auth_recv_rekey_flag, dec_msg, recv_dh_public_key = AES_decrypt_and_verify(args, key, enc_msg, session_salt, expected_seq_num)
    stop_time = latency_test.perf_counter()
    [latency_test.decrypt_average_latency, latency_test.decrypt_average_counter] = latency_test.add_to_average(latency_test.decrypt_average_latency, latency_test.decrypt_average_counter, stop_time - start_time)

print(f"encrypt_average_latency: {latency_test.encrypt_average_latency}")
print(f"decrypt_average_latency: {latency_test.decrypt_average_latency}")