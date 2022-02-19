from seal import *
from seal_helper import *
import time
import SC
import math
import numpy as np
from tqdm import tqdm

def Homo_Stochastic_test():
    #-----init-------------------------------------------------
    parms = EncryptionParameters(scheme_type.CKKS)
    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    # parms.set_coeff_modulus(CoeffModulus.Create(poly_modulus_degree, [56, 35, 35, 56]))
    parms.set_coeff_modulus(CoeffModulus.Create(poly_modulus_degree, [60,40,40,60]))

    context = SEALContext.Create(parms)
    scale = pow(2.0, 40)
    print_parameters(context)

    # loop = 100
    
    # time cnt
    encodetime = 0
    encrytime = 0
    opetime = 0
    decrytime = 0
    decodetime = 0
    
    OpeResult = 0
    # Resultlist = []
    
    #plain text
    # m1 = 0.5
    
    plainlist = []
    for i in range(201):
        plainlist.append(round(-1+i*0.01,3))
    x = np.array([plainlist])
    y1 = x*x*x+x*x+x+1
    error = []
    ave_error=[]
    
    # for loopcnt in tqdm([1,2,5,10,20,50]):
    for loopcnt in tqdm([1,2,3,4,5,6,7,8,9,10]):
    # for loopcnt in tqdm([1]):
    
        resultlist=[]
        for m_i in tqdm(plainlist):
            OpeResult = 0
            for _ in range(loopcnt):
                # -----key gen--------------------------------------------
                # start = time.perf_counter()
                keygen = KeyGenerator(context)
                public_key = keygen.public_key()
                secret_key = keygen.secret_key()
                relin_keys = keygen.relin_keys()
                encryptor = Encryptor(context, public_key)
                evaluator = Evaluator(context)
                decryptor = Decryptor(context, secret_key)

                encoder = CKKSEncoder(context)
                slot_count = encoder.slot_count()
                inputs = DoubleVector()
                # print("Number of slots: " + str(slot_count))
                # row_size = int(slot_count / 2)
                #----encode------------------------------------------------
                time2 = time.perf_counter()

                for i in range(slot_count-1):
                    if i == 0:
                        inputs.append(m_i)
                    inputs.append(0.0)
                # print(len(inputs))

                plain_one = Plaintext()
                encoder.encode(1.0, scale, plain_one)

                x_plain = Plaintext()
                encoder.encode(inputs, scale, x_plain)

                encodetime += time.perf_counter() - time2
                # -----encrypt---------------------------------------------------
                time3 = time.perf_counter()
                x_encrypted = Ciphertext()
                encryptor.encrypt(x_plain, x_encrypted)

                encrytime += time.perf_counter() - time3
                # -----op-----------------------------------------
                time4 = time.perf_counter()
                sqar_encrypted = Ciphertext()
                #x^2
                evaluator.square(x_encrypted, sqar_encrypted)
                evaluator.relinearize_inplace(sqar_encrypted, relin_keys)
                # print("    + Scale of x^2 before rescale: " +
                #   "%.0f" % math.log(sqar_encrypted.scale(), 2) + " bits")
                
                evaluator.rescale_to_next_inplace(sqar_encrypted)
                # print("    + Scale of x^2 after rescale: " +
                #   "%.0f" % math.log(sqar_encrypted.scale(), 2) + " bits")
                
                
                # print("-" * 50)
                # print("Compute and rescale x.")
                x1_encrypted_one = Ciphertext()
                evaluator.multiply_plain(x_encrypted, plain_one, x1_encrypted_one)
                # print("    + Scale of PI*x before rescale: " +
                    # "%.0f" % math.log(x1_encrypted_one.scale(), 2) + " bits")
                evaluator.rescale_to_next_inplace(x1_encrypted_one)
                # print("    + Scale of PI*x after rescale: " +
                    # "%.0f" % math.log(x1_encrypted_one.scale(), 2) + " bits")
                    
                #x^3
                x3_encrypted = Ciphertext()
                # print("    + Scale of PI*x after rescale: " +
                #     "%.0f" % math.log(x_encrypted.scale(), 2) + " bits")
                # evaluator.rescale_to_next_inplace(x_encrypted)
                # print("    + Scale of PI*x after rescale: " +
                #     "%.0f" % math.log(x_encrypted.scale(), 2) + " bits")
                
                # evaluator.multiply(sqar_encrypted,x_encrypted,x3_encrypted)
                evaluator.multiply(sqar_encrypted,x1_encrypted_one,x3_encrypted)
                
                evaluator.relinearize_inplace(x3_encrypted, relin_keys)
                # print("    + Scale of x^3 before rescale: " +
                #   "%.0f" % math.log(x3_encrypted.scale(), 2) + " bits")
                evaluator.rescale_to_next_inplace(x3_encrypted)
                # print("    + Scale of x^3 after rescale: " +
                #   "%.0f" % math.log(x3_encrypted.scale(), 2) + " bits")
                
                # print("-" * 50)
                # print("Parameters used by all three terms are different.")
                # print("    + Modulus chain index for x3_encrypted: " +
                #     str(context.get_context_data(x3_encrypted.parms_id()).chain_index()))
                # print("    + Modulus chain index for sqar_encrypted: " +
                #     str(context.get_context_data(sqar_encrypted.parms_id()).chain_index()))
                # print("    + Modulus chain index for x_encrypted: " +
                #     str(context.get_context_data(x_encrypted.parms_id()).chain_index()))
                # print("    + Modulus chain index for plain: " +
                #     str(context.get_context_data(plain_one.parms_id()).chain_index()))
                # print("-" * 50)
            
                # print("-" * 50)
                # print("The exact scales of all three terms are different:")
                # print("    + Exact scale in x^3: " + "%.10f" % math.log(x3_encrypted.scale(), 2))
                # print("    + Exact scale in x^2: " + "%.10f" % math.log(sqar_encrypted.scale(), 2))
                # print("    + Exact scale in   x: " + "%.10f" % math.log(x_encrypted.scale(), 2))
                # print("    + Exact scale in   1: " + "%.10f" % math.log(plain_one.scale(), 2))

                # print("-" * 50)
                # print("Normalize scales to 2^40.")
                x3_encrypted.set_scale(pow(2.0, 40))
                sqar_encrypted.set_scale(pow(2.0, 40))
                x_encrypted.set_scale(pow(2.0, 40))
                
                
                # print("-" * 50)
                # print("Normalize encryption parameters to the lowest level.")
                last_parms_id = x3_encrypted.parms_id()
                evaluator.mod_switch_to_inplace(sqar_encrypted, last_parms_id)
                evaluator.mod_switch_to_inplace(x_encrypted, last_parms_id)
                evaluator.mod_switch_to_inplace(plain_one, last_parms_id)

                # encrypted_result = Ciphertext()
                evaluator.add_inplace(x3_encrypted, sqar_encrypted)
                evaluator.add_inplace(x3_encrypted, x_encrypted)
                evaluator.add_plain_inplace(x3_encrypted, plain_one)

                opetime += time.perf_counter() - time4
                #-----decrypt----------------------------------------------------
                time5 = time.perf_counter()
                
                plain_result = Plaintext()
                decryptor.decrypt(x3_encrypted, plain_result)
                
                decrytime += time.perf_counter() - time5

                #-----decode-----------------------------------------------------
                time6 = time.perf_counter()
                
                pod_result = DoubleVector()
                encoder.decode(plain_result, pod_result)
                
                decodetime += time.perf_counter() - time6
                #-----Stochastic2Binary------------------------------------------
                OpeResult += pod_result[0]
                # print(pod_result)
                # Resultlist.append(pod_result[0])
            resultlist.append(OpeResult/loopcnt)
        resultlist = np.array([resultlist])
        tmp = abs(y1 - resultlist)
        ave_error.append(np.average(tmp))
        error.append(np.max(tmp))
        print(str(loopcnt)+" average result")
        if loopcnt == 1:
            print(resultlist.tolist())
        print(ave_error)
        print(error)
        # print(Result*2)

    # square_plus_x = pod_result + SC.B2S_IBP(m1,M,SNsize)
    # print(SC.S2B_IBP(square_plus_x,M)*2)
    # square_plus_x_plus_one = square_plus_x + SC.B2S_IBP(1.0,M,SNsize)
    # print(SC.S2B_IBP(square_plus_x_plus_one,M)*3)
    # print("Loop:",loop)
    # print("Encode:",encodetime/loop)
    # print("Encrypt:",encrytime/loop)
    # print("Operation:",opetime/loop)
    # print("Decryption:",decrytime/loop)
    # print("Decode:",decodetime/loop)
    # print("Result:",OpeResult/loop)
    # Resultlist = np.array(Resultlist)
    # print("VAR:",np.var(Resultlist))
    # print(Resultlist)




if __name__ == "__main__":
    Homo_Stochastic_test()
