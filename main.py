#Imports
from fastapi import FastAPI
from warning_messages import display_warning
from detoxify_model import analyze_text
from chatgpt_API import chatgpt, main, __prompt
from detoxify import Detoxify

#Bbro API
app = FastAPI()

@app.get("/bbro")

def sistema(content):
    #funcion detoxify
    tox_rate = analyze_text(model, content)

    #if ofensivo --> función chatGPT
    if (tox_rate == True ):
        label = chatgpt(content)
    else:
        label = "innofensive"

    #label --> función warning
    display_warning(label)