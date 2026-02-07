FROM python:3.11-slim

WORKDIR /app

# Copy shared Sycope SDK from repo root.
COPY sycope/ /app/sycope/

# Copy TrueID connector.
COPY integrations/sycope/ /app/integrations/sycope/

WORKDIR /app/integrations/sycope

RUN pip install --no-cache-dir -r requirements.txt

# sys.path.insert goes ../../ to /app where sycope/ lives.
ENV PYTHONPATH="/app"

CMD ["python3", "trueid_sync.py"]
