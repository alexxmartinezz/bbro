# Function to display the warning message based on the label
def display_warning(label):
    if label == "fatphobia":
        print("Caution: The content you are about to view may contain material that promotes negative stereotypes or discrimination based on a person's weight or body size. Please be considerate of the potential harm such content can cause.")
    elif label == "machismo":
        print("Warning: The content you're about to see may involve the endorsement or glorification of traditional male dominance and behaviors. It's essential to recognize the impact such content can have on gender equality and respectful relationships.")
    elif label == "sexism":
        print("Alert: The content you're accessing may contain gender-based discrimination, stereotypes, or offensive language. Let's be mindful of the potential harm and perpetuation of unequal treatment this content may contribute to.")
    elif label == "racism":
        print("Heads up: The content you're viewing may include material that promotes racial discrimination, prejudice, or stereotypes. Let's remember the importance of respecting diversity and avoiding content that fuels division.")
    elif label == "xenophobia":
        print("Important: The content you're engaging with may exhibit a bias against people from different cultures or nationalities. It's crucial to recognize the harm that such content can cause and promote acceptance of diversity.")
    elif label == "homophobia":
        print("Attention: The content you're about to encounter may contain material that discriminates against or stigmatizes individuals based on their sexual orientation. Let's be aware of the potential harm such content can inflict.")
    elif label == "innofensive":
        print("The content is not offensive")
    else:
        print("No warning message available for this label.")