# Fixture for the smoke test: one outbound call with no timeout.
import requests


def get_price(symbol):
    """Return the latest price for a stock symbol."""
    resp = requests.get(f"https://api.example.com/v1/price/{symbol}")
    return resp.json()["price"]
