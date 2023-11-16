#Imports
import openai
import typer
from rich import print
from rich.table import Table

# Reemplaza esto con tu clave de API real
openai.api_key = ""

def chatgpt(prompt):
    model='gpt-3.5-turbo'
    messages = [
        {"role": "system", "content": "You are a model that classifies offensive content into one of the following labels: fatphobia, sexism, racism, xenophobia, homophobia. Your answer MUST only be the label."},
        {"role": "user", "content": "Text to analyze: " + prompt }
    ]
    response = openai.chat.completions.create(
        model=model,
        messages=messages,
        temperature=0
    )
    label = response.choices[0].message.content
    return label