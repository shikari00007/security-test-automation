import torch
from transformers import AutoModel

REVISION = "0123456789abcdef0123456789abcdef01234567"


def load_remote(name):
    # trust_remote_code=True is never used; weights are pinned and safetensors-only
    return AutoModel.from_pretrained(name, revision=REVISION, trust_remote_code=False, use_safetensors=True)


def load_weights(path):
    return torch.load(path, weights_only=True)
