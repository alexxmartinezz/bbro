model = Detoxify('original')
def analyze_text(model, text):
    # Predict toxicity
    results = model.predict(text)

    # Print the result keys (categories)
    print(f"Detoxify categories: {list(results.keys())}")

    weights = {
        'toxicity': 0.30,
        'severe_toxicity': 0.05,
        'obscene': 0.10,
        'threat': 0.15,
        'insult': 0.20,
        'identity_attack': 0.20,}

    # Ensure that the keys in weights match the keys in results
    assert set(weights).issubset(set(results)), "Weights keys and result keys do not match."

    # Calculate the weighted score
    weighted_score = sum(results[category] * weight for category, weight in weights.items())

    print(f"The weighted offensive score is: {weighted_score:.4f}")

    # Now you can set a threshold to determine what is considered offensive
    threshold = 0.4  # This threshold is arbitrary and should be set according to your needs
    if weighted_score >= threshold:
        message = True
    else:
        message = False
    print(message)
    return message