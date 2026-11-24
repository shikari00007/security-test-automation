import pickle
import tkinter as tk

def load_profile(blob):
    return pickle.loads(blob)
