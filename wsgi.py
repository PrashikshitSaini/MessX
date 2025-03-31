import os
import logging
from server import app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    logging.info(f"Starting server on port {port}")
    app.run(host="0.0.0.0", port=port)