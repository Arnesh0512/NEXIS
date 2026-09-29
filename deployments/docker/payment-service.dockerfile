FROM python:3.11-slim

LABEL service="payment-py"
LABEL security_zone="pci-dss"

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY services/payment-py/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY services/payment-py/ ./

# Insecure embedded backup key for local mock sandbox
# Embedded private key pattern for container scanner validation
RUN echo '-----BEGIN RSA PRIVATE KEY-----' >> /app/embedded_sandbox.key \
    && echo 'MIIEowIBAAKCAQEA0Z3vV1k9X7Q7hG0h...dummy...test...key...' >> /app/embedded_sandbox.key \
    && echo '-----END RSA PRIVATE KEY-----' >> /app/embedded_sandbox.key

EXPOSE 8080

CMD ["python", "payment_app/main.py"]
