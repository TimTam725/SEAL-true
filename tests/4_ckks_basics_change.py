import math
from seal import *
from seal_helper import *
import time
import random


def example_ckks_basics():
    # print_example_banner("Example: CKKS Basics")

    parms = EncryptionParameters(scheme_type.CKKS)

    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.Create(
        poly_modulus_degree, [56,35,35,35,56]))

    scale = pow(2.0, 35)
    context = SEALContext.Create(parms)
    # print_parameters(context)

    keygen = KeyGenerator(context)
    public_key = keygen.public_key()
    secret_key = keygen.secret_key()
    relin_keys = keygen.relin_keys()

    encryptor = Encryptor(context, public_key)
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, secret_key)

    encoder = CKKSEncoder(context)
    slot_count = encoder.slot_count()
    # print("Number of slots: " + str(slot_count))


    # print("Input vector: ")
    # print_vector(inputs, 3, 7)

    # print("Evaluating polynomial PI*x^3 + 0.4x + 1 ...")

    exam_count = 10000 
    enctime = 0
    dectime = 0
    for i in range(exam_count):
        inputs = DoubleVector()
        curr_point = 0.0
        step_size = 1.0 / (slot_count - 1)

        for i in range(slot_count):
            inputs.append(random.random())
            # inputs.append(curr_point)
            curr_point += step_size
        '''
        We create plaintexts for PI, 0.4, and 1 using an overload of CKKSEncoder::encode
        that encodes the given floating-point value to every slot in the vector.
        '''
        # plain_coeff3 = Plaintext()
        # plain_coeff1 = Plaintext()
        # plain_coeff0 = Plaintext()
        # encoder.encode(3.14159265, scale, plain_coeff3)
        # encoder.encode(0.4, scale, plain_coeff1)
        # encoder.encode(1.0, scale, plain_coeff0)

        x_plain = Plaintext()
        # print("-" * 50)
        # print("Encode input vectors.")
        encoder.encode(inputs, scale, x_plain)
        x1_encrypted = Ciphertext()
        time_encrypt_start = time.perf_counter()
        encryptor.encrypt(x_plain, x1_encrypted)
        time_encrypt_end = time.perf_counter()
        # print(f"enc time : {time_encrypt_end - time_encrypt_start}")
        enctime += time_encrypt_end - time_encrypt_start
        # print(f"encrypt time : {enctime}")

        '''
        Decrypt, decode, and print the result.
        '''

        plain_result = Plaintext()
        time_decrypt_start = time.perf_counter()
        decryptor.decrypt(x1_encrypted, plain_result)
        time_decrypt_end = time.perf_counter()
        # print(f"dec time : {time_decrypt_end - time_decrypt_start}")
        dectime += time_decrypt_end - time_decrypt_start
        # result = DoubleVector()
        # encoder.decode(plain_result, result)
        # print("    + Computed result ...... Correct.")
        # print_vector(result, 3, 7)

    print(f"enctime : {enctime / exam_count}")
    print(f"dectime : {dectime / exam_count}")


if __name__ == '__main__':
    example_ckks_basics()
