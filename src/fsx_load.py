#!/usr/bin/python3  
from bcc import BPF
import ctypes as ct
import torch

# We need to access the packed parameters as it has the quantized weights and bias
# We need to access that and write that to a ebpf map which we then have to pin it so that
# it is accessible to the other ebpf programs.

program = r"""
BPF_ARRAY(q_weight_param, u8, size=9)
"""

# Load the BPF program
b = BPF(text=bpf_program)

w = (torch.load('./src/model_weights.pth'))
print(w)

for i in range(len(w['linear._packed_params._packed_params'][0])):
    b["q_weight_param"][i] = w['linear._packed_params._packed_params'][0][i]

b["q_weight_param"][8] = w['linear._packed_params._packed_params'][1] # bias value

# Pining the map to the map path
pinned_map_path = "/sys/fs/bpf/q_weight_param"
b['q_weight_param'].pin(pinned_map_path)


"""
Some output for reference : 

for i in w:
  print("Key:",i)
  print("Value:",(w[i]))

####
Key: linear.scale
Value: tensor(398330.9688)
Key: linear.zero_point
Value: tensor(84)
Key: linear._packed_params.dtype
Value: torch.qint8
Key: linear._packed_params._packed_params
Value: (tensor([[ 0.0000, -0.2126,  0.2817, -0.0239, -0.2259, -0.1382,  0.2817, -0.1196]],
       size=(1, 8), dtype=torch.qint8,
       quantization_scheme=torch.per_tensor_affine, scale=0.002657087752595544,
       zero_point=0), Parameter containing:
tensor([0.0278], requires_grad=True))
Key: quant.scale
Value: tensor([944881.8750])
Key: quant.zero_point
Value: tensor([0])
###
"""