from seal import *
from seal_helper import *
import time
import math
from tqdm import tqdm

#param
parms = EncryptionParameters(scheme_type.CKKS)
poly_modulus_degree = 8192
parms.set_poly_modulus_degree(poly_modulus_degree)
primes = [56,35,35,35,56]

parms.set_coeff_modulus(CoeffModulus.Create(poly_modulus_degree, primes))
context = SEALContext.Create(parms)
scale = pow(2.0, 35)

print_parameters(context)

keygen = KeyGenerator(context)
public_key = keygen.public_key()
secret_key = keygen.secret_key()
relin_keys = keygen.relin_keys()
gal_keys = keygen.galois_keys()
encryptor = Encryptor(context, public_key)
evaluator = Evaluator(context)
decryptor = Decryptor(context, secret_key)


encoder = CKKSEncoder(context)
slot_count = encoder.slot_count()

#weight and bias
def load_bias(path):
    f = open(path)
    data = f.read()
    f.close()
    lines = data.split('\n')
    bias = []
    # print("debug:",lines)
    for line in lines[:-1]:
        bias.append(float(line))

    bias = DoubleVector(bias)
    bias_plain = Plaintext()
    encoder.encode(bias,scale,bias_plain)
    bias_encrypted = Ciphertext()
    encryptor.encrypt(bias_plain, bias_encrypted)

    return bias_encrypted


def load_weight(path):
    f = open(path)
    data = f.read()
    f.close()
    lines = data.split('\n')
    weight = []
    for line in lines[:-1]:
        weight.append(list(map(float,line.split())))
    if len(weight) == 3:
        weight.append([0.0,0.0,0.0,0.0])

    #diagonal order
    d = []
    for i in range(4):
        d.append([weight[0][i],weight[1][(i+1)%4],weight[2][(i+2)%4],weight[3][(i+3)%4]])

    weight_diag = []
    for i in range(4):
        d[i] = DoubleVector(d[i])
        weight_plain = Plaintext()
        encoder.encode(d[i],scale,weight_plain)
        weight_encrypted = Ciphertext()
        encryptor.encrypt(weight_plain, weight_encrypted)
        weight_diag.append(weight_encrypted)

    return weight_diag


def load_enc_iris(path):
    f = open(path)
    data = f.read()
    f.close()
    lines = data.split('\n')
    iris = []
    for line in lines[:-1]:
        iris.append(float(line))
    iris = iris + iris #for Rotation

    iris = DoubleVector(iris)
    iris_plain = Plaintext()
    encoder.encode(iris,scale,iris_plain)
    iris_encrypted = Ciphertext()
    encryptor.encrypt(iris_plain, iris_encrypted)

    return iris_encrypted

#NN
def fc1(insig,weight,bias):

    cipher_mul = Ciphertext()
    evaluator.multiply(weight[0],insig,cipher_mul)
    evaluator.relinearize_inplace(cipher_mul, relin_keys)
    evaluator.rescale_to_next_inplace(cipher_mul)
    for i in range (1,4):
        rotated = Ciphertext()
        evaluator.rotate_vector(insig, i, gal_keys, rotated)

        tmp = Ciphertext()
        evaluator.multiply(weight[i],rotated,tmp)
        evaluator.relinearize_inplace(tmp, relin_keys)
        evaluator.rescale_to_next_inplace(tmp)

        evaluator.add_inplace(cipher_mul,tmp)

    parms_id = cipher_mul.parms_id()
    evaluator.mod_switch_to_inplace(bias, parms_id)

    cipher_mul.set_scale(2**math.log(bias.scale(), 2))

    evaluator.add_inplace(cipher_mul,bias)


    return cipher_mul



def squaring (insig):

    evaluator.square_inplace(insig)
    evaluator.relinearize_inplace(insig, relin_keys)
    evaluator.rescale_to_next_inplace(insig)

    return insig


def fc2(insig,weight,bias):
    #for Rotation
    rot_input = Ciphertext()
    evaluator.rotate_vector(insig, -4, gal_keys, rot_input)
    evaluator.add_inplace(insig,rot_input)

    insig.set_scale(scale*(2**10))
    parms_id = insig.parms_id()
    evaluator.mod_switch_to_inplace(weight[0], parms_id)

    cipher_mul = Ciphertext()
    evaluator.multiply(weight[0],insig,cipher_mul)
    evaluator.relinearize_inplace(cipher_mul, relin_keys)
    evaluator.rescale_to_next_inplace(cipher_mul)
    for i in range (1,4):
        evaluator.mod_switch_to_inplace(weight[i], parms_id)

        rotated = Ciphertext()
        evaluator.rotate_vector(insig, i, gal_keys, rotated)

        tmp = Ciphertext()
        evaluator.multiply(weight[i],rotated,tmp)
        evaluator.relinearize_inplace(tmp, relin_keys)
        evaluator.rescale_to_next_inplace(tmp)

        evaluator.add_inplace(cipher_mul,tmp)

    parms_id = cipher_mul.parms_id()
    evaluator.mod_switch_to_inplace(bias, parms_id)

    cipher_mul.set_scale(2**math.log(bias.scale(), 2))

    evaluator.add_inplace(cipher_mul,bias)

    return cipher_mul

def get_label(path):
    f = open(path)
    data = f.read()
    f.close()
    label = data.split('\n')
    return int(label[0])

def argmax(insig):
    return insig.index(max(insig))


if __name__ == "__main__":
    data_size = 30
    acc = 0
    enctime = 0
    fc1time = 0
    nontime = 0
    fc2time = 0
    dectime = 0
    loop = 1

    for _ in range(loop):
        for i in range(data_size):
            bias1 = load_bias("./data/model/iris_square_nonC/fc1.bias.txt")
            bias2 = load_bias("./data/model/iris_square_nonC/fc2.bias.txt")
            weight1 = load_weight("./data/model/iris_square_nonC/fc1.weight.txt")
            weight2 = load_weight("./data/model/iris_square_nonC/fc2.weight.txt")

            time1 = time.perf_counter()
            iris = load_enc_iris("./data/iris-scale/"+str(i+120)+"/input.txt")
            enctime += time.perf_counter() - time1

            time2 = time.perf_counter()
            fc1_out = fc1(iris,weight1,bias1)
            fc1time += time.perf_counter() - time2

            # print("full connection 1",fc1_out)
            # inference = []
            # Result = Plaintext()
            # decryptor.decrypt(fc1_out, Result)
            # pod_result = DoubleVector()
            # encoder.decode(Result, pod_result)
            # inference.append([float(x) for x in pod_result[:4]])
            # print(inference)

            time3 = time.perf_counter()
            squaring_out = squaring(fc1_out)
            nontime += time.perf_counter() - time3

            # print("activation function",squaring_out)
            # inference = []
            # Result = Plaintext()
            # decryptor.decrypt(squaring_out, Result)
            # pod_result = DoubleVector()
            # encoder.decode(Result, pod_result)
            # inference.append([float(x) for x in pod_result[:10]])
            # print(inference)

            time4 = time.perf_counter()
            fc2_out = fc2(squaring_out,weight2,bias2)
            fc2time += time.perf_counter() - time4

            # print("full connection 2",fc2_out)
            # inference = []
            # Result = Plaintext()
            # decryptor.decrypt(fc2_out, Result)
            # pod_result = DoubleVector()
            # encoder.decode(Result, pod_result)
            # inference = [float(x) for x in pod_result[:3]]
            # print(inference)

            label = get_label("./data/iris-scale/"+str(i+120)+"/label.txt")

            inference = []
            time5 = time.perf_counter()
            Result = Plaintext()
            decryptor.decrypt(fc2_out, Result)
            pod_result = DoubleVector()
            encoder.decode(Result, pod_result)
            inference = [float(x) for x in pod_result[:3]]
            dectime += time.perf_counter() - time5

            if argmax(inference) == label:
                acc += 1

    print("SR",acc/loop)
    print("Enc",enctime/data_size/loop)
    print("FC1",fc1time/data_size/loop)
    print("ACT",nontime/data_size/loop)
    print("FC2",fc2time/data_size/loop)
    print("Dec",dectime/data_size/loop)
