#!/usr/bin/env python
# coding: utf-8

from scapy.all import scapy
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier, export_graphviz
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import GridSearchCV

import re
import os
import time
import pydot
import joblib
import numpy as np
import matplotlib.image as mpimg
import matplotlib.pyplot as plt


# ******************************************************************************************
def TCP_analyze(data: list, flow: list):
    length = []
    for each in flow:
        length.append(len(data[each - 1]))
    Length_Max = np.max(length)
    Length_Min = np.min(length)
    Length_Average = np.average(length)
    return Length_Average, Length_Max, Length_Min


# ******************************************************************************************
def Raw_analyze(data: list, flow: list):
    Raw_length = []
    for each in flow:
        try:
            Raw_length.append(len(data[each - 1].getlayer('Raw')))
        except:
            pass
    if not Raw_length:
        Raw_length = [0]
    Raw_Length_Max = np.max(Raw_length)
    Raw_Length_Min = np.min(Raw_length)
    Raw_Length_Average = np.average(Raw_length)
    return Raw_Length_Average, Raw_Length_Max, Raw_Length_Min


# ******************************************************************************************
def data_separate(data, rate):
    ctl = 1
    train = []
    test = []
    train_data = []
    test_data = []
    np.random.seed(412)
    while (ctl):
        temp = np.random.randint(0, len(data))
        if temp not in train:
            train.append(temp)
        if len(train) == int(len(data) * rate):
            ctl = 0
    for i in range(len(data)):
        if i not in train:
            test.append(i)
    for i in train:
        train_data.append(data[i, :])
    for i in test:
        test_data.append(data[i, :])
    train_data = np.array(train_data)
    test_data = np.array(test_data)
    return train_data, test_data


# ******************************************************************************************
def clf_score(clf, test_features, test_type, score_type=1):
    # score_type: TCP为0,SSH为1,TLS为2 (默认为1)
    predict_type = clf.predict(test_features)
    # print(predict_type)
    TP = 0
    FP = 0
    FN = 0
    TN = 0
    for test, predict in zip(test_type, predict_type):
        test = int(test)
        predict = int(predict)
        if (test == score_type) and (predict == score_type):
            TP += 1
        elif (test != score_type) and (predict == score_type):
            FP += 1
        elif (test == score_type) and (predict != score_type):
            FN += 1
        elif (test != score_type) and (predict != score_type):
            TN += 1
    # 查准率 precision
    try:
        precision = TP/(TP+FP)
    except ZeroDivisionError:
        precision = 0

    # 查全率 recall
    try:
        recall = TP/(TP+FN)
    except ZeroDivisionError:
        recall = 0

    # 准确率 accuracy
    try:
        accuracy = (TP+TN)/(TP+FP+TN+FN)
    except ZeroDivisionError:
        accuracy = 0

    # 综合评价 F-Measure
    try:
        F_Measure = 2*precision*recall/(precision+recall)
    except ZeroDivisionError:
        F_Measure = 0

    # 完整性 completeness
    try:
        completeness = recall/precision
    except ZeroDivisionError:
        completeness = 0

    # 未识别率 unrecognized
    unrecognized = 0

    return precision, recall, accuracy, F_Measure, completeness, unrecognized


# ******************************************************************************************
# 读取pcap文件数据
os.system('chcp 65001')
# file_path = r'F:\Data\0521.pcap'
file_path = r'F:\Data\0522.pcap'
start = time.time()
f = open(file_path, 'rb')
fpcap = scapy.utils.rdpcap(f)
f.close()
end = time.time()
print('Dataset load finished!  During: {:.2f}s'.format(end - start))
print()
del f, file_path

# ******************************************************************************************
# 区分数据的会话流Session
start = time.time()
count = 0
data = {}
for packet in fpcap:
    count += 1
    if packet.haslayer('TCP'):
        src_ip = packet.payload.src
        src_port = packet.payload.sport
        dst_ip = packet.payload.dst
        dst_port = packet.payload.dport
        forward = src_ip + ':' +             str(src_port) + '-' + dst_ip + ':' + str(dst_port)
        backward = dst_ip + ':' +             str(dst_port) + '-' + src_ip + ':' + str(src_port)
        if forward in data.keys():
            data[forward].append(count)
        elif backward in data.keys():
            data[backward].append(count)
        else:
            data.setdefault(forward, [])
            data[forward].append(count)
del packet, count, src_ip, src_port, dst_ip, dst_port, forward, backward

# ******************************************************************************************
# 对数据包的报文内容进行正则匹配，若能成功匹配则标签为SSH流量会话流。
protocol = {}
for key in data.keys():
    temp = data[key]
    raw_string = []
    for count in range(len(temp)):
        packet = fpcap[temp[count]-1]
        if packet.haslayer('Raw'):
            raw_string.append(packet.getlayer('Raw'))
        else:
            protocol.setdefault(key, 'TCP')
    for each in raw_string:
        if re.match(r'(.*)[o|O][p|P][e|E][n|N][s|S][s|S][h|H](.*)', str(each['Raw'])):  # re.SSH
            protocol[key] = 'SSH'
            break
        elif re.match(r'(.*)[t|T][l|L][s|S](.*)', str(each['Raw'])):    # re.TLS
            protocol[key] = 'TLS'
            break
del key, temp, count, each, raw_string

# ******************************************************************************************
# 提取会话流的特征(TCP为0，SSH为1，TLS为2)
# [Length_Average, Length_Max, Length_Min, Raw_Length_Average, Raw_Length_Max, Raw_Length_Min]
features_type = np.zeros([len(data), 7])
count = 0

for key in data.keys():
    Length_Average, Length_Max, Length_Min = TCP_analyze(fpcap, data[key])
    Raw_Length_Average, Raw_Length_Max, Raw_Length_Min = Raw_analyze(
        fpcap, data[key])

    if protocol[key] == 'TCP':  # TCP为0
        temp = 0
    elif protocol[key] == 'SSH':    # SSH为1
        temp = 1
    elif protocol[key] == 'TLS':    # TLS为2
        temp = 2
    features_type[count] = [Length_Average, Length_Max, Length_Min,
                            Raw_Length_Average, Raw_Length_Max, Raw_Length_Min, temp]
    count += 1
del count, key, Length_Average, Length_Max, Length_Min, Raw_Length_Average, Raw_Length_Max, Raw_Length_Min,

# ******************************************************************************************
# 机器学习部分
# 预处理 train:test=0.8:0.2
trainingRate = 0.8
train_data, test_data = data_separate(features_type, trainingRate)
train_features = train_data[:, :-1]
train_type = train_data[:, -1]
test_features = test_data[:, :-1]
test_type = test_data[:, -1]
end = time.time()
print('Dataset pre-process finished!  During: {:.2f}s'.format(end - start))
print()

# svm ********************************************************************************************
start = time.time()
print('Begin svc_clf training······')
model = SVC(kernel='rbf')
param_grid = {'C': [1e-3, 1e-2, 1e-1, 1, 10, 100, 1000, 10000, 1E05, 1E06], 'gamma': [0.1, 0.01, 0.001, 0.0001, 'auto']}
grid_search = GridSearchCV(model, param_grid, n_jobs =-1, verbose=2, cv=5)
grid_search.fit(test_features, test_type)
best_parameters = grid_search.best_estimator_.get_params()

svc_clf = SVC(kernel='rbf', C=best_parameters['C'], gamma=best_parameters['gamma'], decision_function_shape='ovr')
svc_clf.fit(train_features, train_type)
joblib.dump(svc_clf, 'svc_clf')
end = time.time()
print('svc_clf training has been done!  During: {:.2f}s'.format(end - start))
print('best C:\t\t' + str(best_parameters['C']))
print('best gamma:\t' + str(best_parameters['gamma']))

for i in [1,2]:
    svc_clf_score = clf_score(svc_clf, test_features, test_type, i)
    if i == 1:
        print('score_type: SSH')
    elif i == 2:
        print('score_type: TLS')
    score = ['precision', 'recall', 'accuracy',
             'F_Measure', 'completeness', 'unrecognized']
    count = 0
    for one in score:
        print('\t'+one+':{:.3f}'.format(svc_clf_score[count]))
        count += 1
    print()
print()

# DecisionTree ***********************************************************************************
start = time.time()
print('Begin tree_clf training······')
# tree_clf = joblib.load(r'tree_clf') #读取保存的DecisionTree模型
model = DecisionTreeClassifier()
param_grid = {'criterion':['gini', 'entropy'], 'max_depth':[5, 4, 3, 2]}
grid_search = GridSearchCV(model, param_grid, n_jobs =-1, verbose=0, cv=5, scoring='recall_macro')
grid_search.fit(test_features, test_type)
best_parameters = grid_search.best_estimator_.get_params()

tree_clf = DecisionTreeClassifier(criterion=best_parameters['criterion'], max_depth=best_parameters['max_depth'])
tree_clf.fit(train_features, train_type)
print(best_parameters['criterion'])
print(best_parameters['max_depth'])
end = time.time()
print('tree_clf training has been done! During: {:.2f}s'.format(end - start))
names = ['Length_Average', 'Length_Max', 'Length_Min',
         'Raw_Length_Average', 'Raw_Length_Max', 'Raw_Length_Min']
with open('./tree.dot', 'w', encoding='utf-8') as f:
    f = export_graphviz(tree_clf,
                        out_file=f,
                        feature_names=names,
                        class_names=['TCP', 'SSH', 'TLS'],
                        rounded=True,
                        filled=True)
(graph,) = pydot.graph_from_dot_file('tree.dot')
graph.write_png('tree.png')
im = mpimg.imread('tree.png')
plt.imshow(im)
plt.axis('off')
plt.show()

for i in [1,2]:
    tree_clf_score = clf_score(tree_clf, test_features, test_type, i)
    if i == 1:
        print('score_type: SSH')
    elif i == 2:
        print('score_type: TLS')
    score = ['precision', 'recall', 'accuracy',
             'F_Measure', 'completeness', 'unrecognized']
    count = 0
    for one in score:
        # print('\t'+one+':{:.3f}'.format(tree_clf_score[count]))
        print('{:.3f}'.format(tree_clf_score[count]),end='\t')
        count += 1
    print()
print()

# RandomForest ************************************************************************************
start = time.time()
print('Begin rnd_clf training······')
# rnd_clf = joblib.load(r'rnd_clf') #读取保存的RandomForest模型
model = RandomForestClassifier(n_jobs=-1)
param_grid = {'n_estimators':[100, 150, 200, 250, 300, 350], 'max_leaf_nodes':[10,15,20], 'max_depth':[3,4,5,6,7]}
# param_grid = {n_estimators:[100, 150, 200, 250, 300, 350], max_leaf_nodes:[], max_depth:[]}
grid_search = GridSearchCV(model, param_grid, n_jobs=-1, verbose=0, cv=5)
grid_search.fit(test_features, test_type)
best_parameters = grid_search.best_estimator_.get_params()

rnd_clf = RandomForestClassifier(n_jobs=-1, n_estimators=best_parameters['n_estimators'], 
                                 max_leaf_nodes=best_parameters['max_leaf_nodes'], max_depth=best_parameters['max_depth'])
print(best_parameters['n_estimators'])
print(best_parameters['max_leaf_nodes'])
print(best_parameters['max_depth'])
rnd_clf.fit(train_features, train_type)
# rnd_clf_score = clf_score(rnd_clf, test_features, test_type)
end = time.time()
print('rnd_clf training has been done! During: {:.2f}s'.format(end - start))

for i in [1,2]:
    rnd_clf_score = clf_score(rnd_clf, test_features, test_type, i)
    if i == 1:
        print('score_type: SSH')
    elif i == 2:
        print('score_type: TLS')
    score = ['precision', 'recall', 'accuracy',
             'F_Measure', 'completeness', 'unrecognized']
    count = 0
    for one in score:
        # print('\t'+one+':{:.3f}'.format(rnd_clf_score[count]))
        print('{:.3f}'.format(rnd_clf_score[count]),end='\t')
        count += 1
    print()
print()

