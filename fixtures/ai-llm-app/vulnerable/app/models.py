import pickle

import requests
import torch
from transformers import AutoModel


def load_remote(name):
    return AutoModel.from_pretrained(name, trust_remote_code=True)


def load_downloaded(url):
    blob = requests.get(url).content
    return pickle.loads(blob)


def load_weights(path):
    return torch.load(path, weights_only=False)
