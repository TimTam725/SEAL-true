import SC
import time
from tqdm import tqdm
from seal import *
from seal_helper import *
import numpy as np
import collections

#init

parms = EncryptionParameters(scheme_type.CKKS)
poly_modulus_degree = 1024
parms.set_poly_modulus_degree(poly_modulus_degree)

parms.set_coeff_modulus(CoeffModulus.Create(poly_modulus_degree, [18]))
context = SEALContext.Create(parms)
scale = pow(2.0, 15)

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

SNsize = int(poly_modulus_degree)
M = 1.000000000000001

#weight and bias
def load_bias(path):
    f = open(path)
    data = f.read() 
    f.close()
    lines = data.split('\n') 
    bias_list = []
    for line in lines[:-1]:
        tmpSN = SC.B2S_IBP(float(line),M,SNsize)
        tmpSN = [complex(tmpSN[i] ,tmpSN[i+1]) for i in range(0, SNsize, 2)]
        bias = ComplexDoubleVector(tmpSN)
        bias_plain = Plaintext()
        encoder.encode(bias,scale,bias_plain)
        bias_encrypted = Ciphertext()
        encryptor.encrypt(bias_plain, bias_encrypted)
        bias_list.append(bias_encrypted)
        
    return bias_list

def load_bias2(path):
    f = open(path)
    data = f.read() 
    f.close()
    lines = data.split('\n') 
    bias_list = []
    for line in lines[:-1]:
        #encode
        bias_plain = Plaintext()
        encoder.encode(float(line),scale,bias_plain)
        #encrypt
        bias_encrypted = Ciphertext()
        encryptor.encrypt(bias_plain, bias_encrypted)
        bias_list.append(bias_encrypted)
    return bias_list


def load_weight1(path):
    f = open(path)
    data = f.read() 
    f.close()
    lines = data.split('\n')
    weight_list = []
    for line in lines[:-1]:
        buf = []
        for ele in list(map(float,line.split())):
            tmpweight = SC.B2S_IBP(float(ele),M,SNsize)
            tmpweight = [complex(tmpweight[i] ,tmpweight[i+1]) for i in range(0, SNsize, 2)]
            weight = ComplexDoubleVector(tmpweight)
            # weight = DoubleVector(SC.B2S_IBP(float(ele),M,SNsize))
            weight_plain = Plaintext()
            encoder.encode(weight,scale,weight_plain)
            weight_encrypted = Ciphertext()
            encryptor.encrypt(weight_plain, weight_encrypted)
            buf.append(weight_encrypted)
        weight_list.append(buf)
    return weight_list


def load_weight2(path):
    f = open(path)
    data = f.read() 
    f.close()
    lines = data.split('\n')
    weight = []
    weight_list = [[[] for _ in range(4)] for _ in range(3)]
    # print(weight_SC)
    
    for line in lines[:-1]:
        weight.append(list(map(float,line.split())))
    
    for _ in range(25):
        for i,row in enumerate(weight):
            for j,ele in enumerate(row):
                tmpweight = SC.B2S_IBP(float(ele),M,SNsize)
                tmpweight = [complex(tmpweight[i] ,tmpweight[i+1]) for i in range(0, SNsize, 2)]
                weight_ele = ComplexDoubleVector(tmpweight)
                # weight_ele = DoubleVector(SC.B2S_IBP(float(ele),M,SNsize))
                weight_plain = Plaintext()
                encoder.encode(weight_ele,scale,weight_plain)
                weight_encrypted = Ciphertext()
                encryptor.encrypt(weight_plain, weight_encrypted)
                weight_list[i][j].append(weight_encrypted)

    return weight_list


def load_iris(path):
    f = open(path)
    data = f.read() 
    f.close()
    lines = data.split('\n') 
    iris = []
    for line in lines[:-1]:
        iris.append(float(line))
    return iris

#NN
def fc1(insig,weight,bias):
    
    for i in range(4):
        for j in range(4):
            evaluator.add_inplace(weight[i][j],insig[j])
        weight[i].append(bias[i])

    return weight


def squaring (insig):
    sq_res = [[] for _ in range(4)]

    for i in range(4):
        my_append = sq_res[i].append
        for j in range(5):
            rotated = Ciphertext()
            evaluator.rotate_vector(insig[i][j], 1, gal_keys, rotated)

            tmp = Ciphertext()
            evaluator.add(insig[i][j],rotated,tmp)

            my_append(tmp)

        for j in range(4):
            for k in range(j+1,5):
                tmp = Ciphertext()
                evaluator.add(insig[i][j],insig[i][k],tmp)

                my_append(tmp)
                my_append(tmp)

    return sq_res


def squaring2 (insig,insig2):
    sq_res = [[] for _ in range(4)]

    for i in range(4):
        my_append = sq_res[i].append
        for j in range(5):
            tmp = Ciphertext()
            
            evaluator.add(insig[i][j],insig2[i][j],tmp)

            my_append(tmp)

        for j in range(4):
            for k in range(j+1,5):
                tmp = Ciphertext()
                evaluator.add(insig[i][j],insig[i][k],tmp)

                my_append(tmp)
                my_append(tmp)


    return sq_res


def flatten(nested_list):
    """2重のリストをフラットにする関数"""
    return [e for inner_list in nested_list for e in inner_list]

def fc2(input,weight,bias):
    
    for i in range(3):
        for j in range(4):
            for k in range(25):
                evaluator.add_inplace(weight[i][j][k],input[j][k])
        weight[i] = flatten(weight[i])
        weight[i].append(bias[i])

    return weight





def get_label(path):
    f = open(path)
    data = f.read() 
    f.close()
    label = data.split('\n') 
    return int(label[0])

def argmax(input):
    return input.index(max(input))

def rotate(l, n):
    return l[-n:] + l[:-n]


if __name__ == "__main__":
    
    data_size = 30
    acc = 0
    loop = 1
    acc_list = []
    B2Stime,Enctime,fc1time,acttime,fc2time,Dectime,S2Btime = 0,0,0,0,0,0,0
    
    for l in tqdm(range(loop)):
        acc = 0
        print("-"*20 + str(l+1) + "th loop" + "-"*20)
        for i in tqdm(range(data_size)):
            
            bias1 = load_bias("./data/model/iris_square_nonC/fc1.bias.txt")
            bias12 = load_bias("./data/model/iris_square_nonC/fc1.bias.txt")
            
            bias2 = load_bias2("./data/model/iris_square_nonC/fc2.bias.txt")
            weight1 = load_weight1("./data/model/iris_square_nonC/fc1.weight.txt")
            weight12 = load_weight1("./data/model/iris_square_nonC/fc1.weight.txt")
            
            weight2 = load_weight2("./data/model/iris_square_nonC/fc2.weight.txt")
            
            iris = load_iris("./data/iris-scale/"+str(i+120)+"/input.txt")
            iris2 = load_iris("./data/iris-scale/"+str(i+120)+"/input.txt")
            
            
            def a(SN):
                return [complex(SN[i] ,SN[i+1]) for i in range(0, SNsize, 2)]

            time1 = time.perf_counter()
            iris = [a(SC.B2S_IBP(x,M,SNsize)) for x in iris]
            iris2 = [a(SC.B2S_IBP(x,M,SNsize)) for x in iris2]
            B2Stime += time.perf_counter() - time1
            

            iris_list = []
            time2 = time.perf_counter()
            for ele in iris:
                iris_ele = ComplexDoubleVector(ele)
                iris_plain = Plaintext()
                encoder.encode(iris_ele,scale,iris_plain)
                iris_encrypted = Ciphertext()
                encryptor.encrypt(iris_plain, iris_encrypted)
                iris_list.append(iris_encrypted)

            iris_list2 = []
            # time2 = time.perf_counter()
            for ele2 in iris2:
                iris_ele2 = ComplexDoubleVector(ele2)
                iris_plain2 = Plaintext()
                encoder.encode(iris_ele2,scale,iris_plain2)
                iris_encrypted2 = Ciphertext()
                encryptor.encrypt(iris_plain2, iris_encrypted2)
                iris_list2.append(iris_encrypted2)
            # Enctime += time.perf_counter() - time2
            Enctime += time.perf_counter() - time2


            time3 = time.perf_counter()
            fc1_out = fc1(iris_list,weight1,bias1)
            fc1time += time.perf_counter() - time3

            fc1_out2 = fc1(iris_list2,weight12,bias12)
            

            time4 = time.perf_counter()
            squaring_out = squaring2(fc1_out,fc1_out2)
            # squaring_out = squaring(fc1_out)
            
            acttime += time.perf_counter() - time4

            time5 = time.perf_counter()
            fc2_out = fc2(squaring_out,weight2,bias2)
            fc2time += time.perf_counter() - time5

            time6 = time.perf_counter()
            for j in range(3):
                for k in range(100):
                    Result = Plaintext()
                    decryptor.decrypt(fc2_out[j][k], Result)
                    pod_result = ComplexDoubleVector()
                    encoder.decode(Result, pod_result)
                    fc2_out[j][k] = pod_result
                Result = Plaintext()
                decryptor.decrypt(fc2_out[j][100], Result)
                pod_result = ComplexDoubleVector()
                encoder.decode(Result, pod_result)
                fc2_out[j][100] = pod_result[0]
            Dectime += time.perf_counter() - time6
            # print("elapsed_time:", encoder.elapsed_time)
            # print("intt_cont:", encoder.intt_count)
            
            # if i == 0 :
            #     print(fc2_out[0][0][:10])
            #S2B
            res = [0,0,0]
            time7 = time.perf_counter()
            for id,row in enumerate(fc2_out):
                # s = time.perf_counter()
                # cnt = np.count_nonzero(np.array([round(x) % 2 for x in flatten(row[:-1])]))
                # cnt =  [round(x) %2 for x in flatten(row[:-1])].count(1)
                # print("debug",time.perf_counter() - s)
                # for ele in row[:-1]:
                #     cnt += [round(x) % 2 for x in ele].count(1)
                    # cnt += sum([round(x) % 2 for x in ele])
                # row[:-1] = [np.array(x).tolist() for x in row[:-1]]
                # for s in range(0,len(row[:-1]),2):
                #     a = row[s]+row[s+1]
                #     cnt += [round(x)%2 for x in a].count(1)
                
                row[:-1] = [np.round(np.array(x)) for x in row[:-1]]
                cnt = np.sum(np.real(np.ravel(row[:-1]))%2) + np.sum(np.imag(np.ravel(row[:-1]))%2)
                # conl = np.round(np.concatenate((np.array(pod_result),np.array(pod_result2),np.array(pod_result3),np.array(pod_result4)),0))
                
                # for s in range(0,len(row[:-1]),2):
                #     a = row[s]+row[s+1]
                #     cnt += [round(x)%2 for x in a].count(1)

                res[id] = M*(100-2*cnt/SNsize) +fc2_out[id][-1]
            S2Btime += time.perf_counter() - time7
                

            label = get_label("./data/iris-scale/"+str(i+120)+"/label.txt")
            # print(argmax(res),label)

            if argmax(res) == label:
                acc += 1
            print(f"{i+1:2}"+"th Inference Complete")
            # print("Items",B2Stime,Enctime,fc1time,acttime,fc2time,Dectime,S2Btime)
            # print("Except Sto",Enctime+fc1time+acttime+fc2time+Dectime)
            # print("All",B2Stime+Enctime+fc1time+acttime+fc2time+Dectime+S2Btime)
        print(str(l+1)+"th SR",acc)
        acc_list.append(acc)
    print("SR",sum(acc_list)/loop)
    print("B2S",B2Stime/data_size/loop)
    print("Enc",Enctime/data_size/loop)
    print("FC1",fc1time/data_size/loop)
    print("ACT",acttime/data_size/loop)
    print("FC2",fc2time/data_size/loop)
    print("Dec",Dectime/data_size/loop)
    print("S2B",S2Btime/data_size/loop)
    a = B2Stime/data_size/loop
    b = Enctime/data_size/loop
    c = fc1time/data_size/loop
    d = acttime/data_size/loop
    e = fc2time/data_size/loop
    f = Dectime/data_size/loop
    g = S2Btime/data_size/loop
    
    print(collections.Counter(acc_list))
    
    # print("ntt_time:", encoder.elapsed_time/encoder.intt_count)
            
    
    
    
            
            
            
            
















