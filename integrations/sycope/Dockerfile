FROM python:3.11-slim

WORKDIR /app

# Copy shared Sycope SDK.
COPY sycope/ /app/sycope/

# Copy TrueID connector.
COPY integrations/sycope/ /app/trueid/

WORKDIR /app/trueid

RUN pip install --no-cache-dir -r requirements.txt

# Adjust sys.path for sycope import.
ENV PYTHONPATH="/app"

CMD ["python3", "trueid_sync.py"]
