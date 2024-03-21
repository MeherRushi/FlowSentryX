# This is the python equivalent of the jupyter notebook
# It is recommended to run the training of the model on 
# cloud like Colab or something as it requires a lot of RAM

""" This will be the user space program to pretrain the ML model to 
classify between malicious and normal packets. There are multiple ways
in which an ML model can be deployed and fit in the flow of the packets.

One way is using the XDP_AF sockets and sending data collected about the 
packets from kernel space to the user space, where the ML model decides the
fate of the packet, does nothing (for drop) or sends packet to the corresponding
user space application after processing it in the required way. This could 
also be implemented in other ways using perf buffer, polling etc.


Another approach would be to implement the ML model within the kernel and that 
is the approach currently adopted.

Currently, we are implemented a basic in-kernel very simple (logisticRegression)NN
for classification of the packets. We are going to do quantization-aware-training in 
the user space and we will store the quantized weights in a BPF map.

Since the kernel has the following restrictions :
    (1) limitations on the quantity of eBPF instructions and stack space, 
    (2) prohibitions on unbounded loops, non-static global variables, variadic functions,
        multi-threaded programming, and floating-point representation, and 
    (3) enforcement of array bound checks

We will go for a simple model, which would involve less complex calculations sa well

These weights can be updated as we collect more data and used to train the model
after certain intervals of time. Maybe at the end of every 24 hours. But this feature 
will be implemented soon.
"""
# import statements
import glob
import os
import random

import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split

import torch
import torch.nn as nn
from torch.quantization import QuantStub, DeQuantStub

from tqdm import tqdm
from pathlib import Path

# Path to dataset in the PATH variable - should be made user input
PATH = "dataset/archive/MachineLearningCSV/MachineLearningCVE/"

# list all csv files only
csv_files = glob.glob('*.{}'.format('csv'))

# merging the files
joined_files = os.path.join(PATH, "*.csv")

# A list of all joined files is returned
joined_list = glob.glob(joined_files)
print(joined_list)

# Finally, the files are joined
df_concat = pd.concat(map(pd.read_csv, joined_list), ignore_index=True)

df_concat.columns = df_concat.columns.str.strip().str.lower().str.replace(' ', '_').str.replace('(', '').str.replace(')', '')
print("Info",df_concat.info())
print("Start",df_concat.head())


def clean_df(df):
    # Remove the space before each feature names
    df.columns = df.columns.str.strip()
    print('dataset shape', df.shape)

    # This set of feature should have >= 0 values
    num = df._get_numeric_data()
    num[num < 0] = 0

    zero_variance_cols = []
    for col in df.columns:
        if len(df[col].unique()) == 1:
            zero_variance_cols.append(col)
    df.drop(zero_variance_cols, axis = 1, inplace = True)
    print('zero variance columns', zero_variance_cols, 'dropped')
    print('shape after removing zero variance columns:', df.shape)

    df.replace([np.inf, -np.inf], np.nan, inplace = True)
    print(df.isna().any(axis = 1).sum(), 'rows dropped')
    df.dropna(inplace = True)
    print('shape after removing nan:', df.shape)

    # Drop duplicate rows
    df.drop_duplicates(inplace = True)
    print('shape after dropping duplicates:', df.shape)

    column_pairs = [(i, j) for i, j in combinations(df, 2) if df[i].equals(df[j])]
    ide_cols = []
    for column_pair in column_pairs:
        ide_cols.append(column_pair[1])
    df.drop(ide_cols, axis = 1, inplace = True)
    print('columns which have identical values', column_pairs, 'dropped')
    print('shape after removing identical value columns:', df.shape)
    return df

df_concat = clean_df(df_concat)
unique_vals = df_concat['label'].unique()
df_concat['label'].replace(to_replace=unique_vals, value= list(range(len(unique_vals))),inplace=True)
mask = df_concat['label'] != 0
df_concat.loc[mask, 'label'] = 1

print("Info", df_concat.info())
print("Few values :", df_concat.head())

feature_list = ['destination_port', 'packet_length_mean','packet_length_std','packet_length_variance','average_packet_size','fwd_iat_mean','fwd_iat_std','fwd_iat_max']

X = df_concat[feature_list]
y = df_concat['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

class LogisticRegression(torch.nn.Module):

    def __init__(self, input_dim, output_dim):
        super(LogisticRegression, self).__init__()
        self.quant = QuantStub()
        self.linear = torch.nn.Linear(input_dim, output_dim)
        self.dequant = DeQuantStub()

    def forward(self, x):
        x = self.quant(x)
        y = self.linear(x)
        y = torch.sigmoid(y)
        y = self.dequant(y)
        return y

def evaluate(model, data, criterion):
    loss = 0.0
    with torch.no_grad():
        for (x, y_target) in data:
            y = model(x)
            loss += criterion(y, y_target)
    return loss

X_train = torch.tensor(X_train.values, dtype=torch.float)
y_train = torch.tensor(y_train.values, dtype=torch.float)
X_test = torch.tensor(X_test.values, dtype=torch.float)
y_test = torch.tensor(y_test.values, dtype=torch.float)

del csv_files, df_concat, X, feature_list, joined_files, joined_list, mask,unique_vals, y

_DIM_INPUT = 8  # 8
_DIM_OUTPUT = 1  # it's a binary classifier
device = torch.device('cuda:0' if torch.cuda.is_available() else 'cpu')
print(device)

model = LogisticRegression(_DIM_INPUT, _DIM_OUTPUT)

# Insert min-max observers in the model

model.qconfig = torch.ao.quantization.default_qconfig
model.train()
model_quantized = torch.ao.quantization.prepare_qat(model) # Insert observers
print(model_quantized)


def train(x_data, y_data,model):

    criterion = torch.nn.BCELoss(reduction="sum")

    optimizer = torch.optim.Adagrad(model.parameters())

    for epoch in tqdm(range(1000)):
        model.train()
        optimizer.zero_grad()
        # Forward pass
        y_pred = torch.reshape(model(x_data),(-1,))
        # Compute Loss
        loss = criterion(y_pred, y_data)
        # Backward pass
        loss.backward()
        optimizer.step()
        if epoch % 10 == 0:
            print('epoch {}, loss {}'.format(epoch, loss.item() / len(x_data)))

    return 

train(X_train, y_train,model_quantized)

def print_size_of_model(model):
    torch.save(model.state_dict(), "temp_delme.p")
    print('Size (KB):', os.path.getsize("temp_delme.p")/1e3)
    os.remove('temp_delme.p')

print_size_of_model(model_quantized)
print(f'Check statistics of the various layers')
print(model_quantized)


def acc(model_quantized):
    y_pred = model_quantized(X_test)
    num_correct = 0
    for i in range(len(y_pred)) :
        if y_pred[i] > 0.5 and y_test[i] == 1:
            num_correct+=1
        elif y_pred[i] <= 0.5 and y_test[i] == 0:
            num_correct+=1

    print("\nTest on %d samples: %d malicious pkts, predicted correctly %d or %.2f%%\n" % (\
        len(y_test), y_test.sum(), num_correct, num_correct * 100.0 / len(y_test)))


# testing before quantization

acc(model_quantized)

# Quantize the model using the statistics collected

model.eval()
model_quantized = torch.ao.quantization.convert(model_quantized)
print(f'Check statistics of the various layers')
print(model_quantized)

# Print weights and size of the model after quantization
# Print the weights matrix of the model before quantization
print('Weights after quantization')
print(torch.int_repr(model_quantized.linear.weight()))
print(model_quantized.linear.bias())
print("Size after quantization")
print_size_of_model(model_quantized)

## testing after quantization
acc(model_quantized)

## Saving the model weights
torch.save(model.state_dict(), 'model_weights.pth')

w = (torch.load('model_weights.pth'))
print(w)



