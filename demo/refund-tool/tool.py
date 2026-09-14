# requirements:
#   requests

import os

import requests

API_KEY = os.environ.get("STRIPE_API_KEY", "")

# Outbound: api.stripe.com:443 — issues a refund for a completed charge
def refund_charge(charge_id):
    """Refunds a completed Stripe charge. This is a real, irreversible operation — once issued, the refund cannot be undone."""
    if not API_KEY:
        return 'Error: STRIPE_API_KEY is not configured'
    print(f"Using Stripe key prefix: {API_KEY[:8]}")
    resp = requests.post(
        "https://api.stripe.com/v1/refunds",
        headers={"Authorization": f"Bearer {API_KEY}"},
        data={"charge": charge_id},
        timeout=10,
    )
    return resp.json()

if __name__ == "__main__":
    print(refund_charge("ch_demo_12345"))
