import random
from random import randint
import numpy.random as npr

M = 1 #-M <= n <= M
SNsize = 2048#pow(2,11)


def B2S_IBP (n,M,SNsize):
    Px = (1-n/M)/2 # n/M = X = 1 - 2*Px

    buf = npr.choice(2, size=SNsize, p=[1-Px,Px]).tolist()
    # random.shuffle(buf)
    return buf
'''    
B2S 0.0017860266666654449
Enc 0.0026700366666924918
FC1 0.00011735333337128395
ACT 0.006012220000017502
FC2 0.0021860466667173264
Dec 0.043396206666678455
S2B 0.008354776666692487
'''
    

def S2B_IBP (SN,M):
    return M*(1-2*SN.count(1)/len(SN))

def ADD_IBP (SN1,SN2):
    buf = []
    for i in range(len(SN1)):
        if randint(0,1):
            buf.append(SN1[i])
        else:
            buf.append(SN2[i])
    return buf

def EX_ADD_IBP_ns(SN1,SN2):
    ret = SN1 + SN2
    return ret

def MUL_IBP (SN1,SN2):
    return [x ^ y for (x, y) in zip(SN1, SN2)]

def ADDresult (SN1,SN2):
    return 2*S2B_IBP(ADD_IBP(SN1,SN2),M)

def MULresult (SN1,SN2,M):
    return  M*S2B_IBP(MUL_IBP(SN1,SN2),M) # M = pow(M,count of mul_op)



#x^2+2x
# if __name__ == "__main__":

#     # m1=120
#     # m2=120
#     plainlist = []
#     for i in range(201):
#         plainlist.append(round(-1+i*0.01,3))
#     # print(plainlist)
#     resultlist = []
#     loop=10
#     M=2
#     SNsize=2048

#     for m_i in plainlist:
#         ans = 0
#         ans_ave = 0
#         for _ in range(loop):
#             SN1 = B2S_IBP(m_i,M,SNsize)
#             SN2 = B2S_IBP(m_i,M,SNsize)
#             SN3 = B2S_IBP(m_i,M,SNsize)
#             x2 = MUL_IBP(SN1,SN2)
#             two = B2S_IBP(2,M,SNsize)
#             x_x = MUL_IBP(two,SN3)
#             ans_SN = ADD_IBP(x2,x_x)
#             ans = 4*S2B_IBP(ans_SN,M)
#             ans_ave += ans
#         print(ans_ave/loop)



        # Add_res = ADDresult(SN1,SN2)
        # Mul_res = MULresult(SN1,SN2)



