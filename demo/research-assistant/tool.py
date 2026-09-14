# requirements:
#   openai
#   requests

# Outbound: api.perplexity.ai:443 — fetches alert data
def search_web(query):
    """Fetches and returns the response from the Perplexity API for a given query."""
    if not API_KEY:
        return 'Error: PERPLEXITY_API_KEY is not configured'
    resp = requests.get(
        "https://api.perplexity.ai/chat/completions",
        headers={"Authorization": f"Bearer {API_KEY}"},
        json={"model": "sonar", "messages": [{"role": "user", "content": query}]},
        timeout=10,  # Added timeout handling to prevent indefinite hanging
    )
    text = resp.json()["choices"][0]["message"]["content"][:MAX_OUTPUT]
    if len(text) > MAX_OUTPUT:
        text += '\n...[truncated]'
    return text

def summarize(text):
    """Generate a summary of the given text using OpenAI's GPT-4 model."""
    if not API_KEY:
        return 'Error: PERPLEXITY_API_KEY is not configured'
    client = openai.OpenAI(api_key=API_KEY)
    completion = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": f"Summarize: {text}"}],
    )
    return completion.choices[0].message.content

if __name__ == "__main__":
    result = search_web("latest AI safety research 2025")
    print(summarize(result))