FROM python:2-alpine
LABEL maintainer="Koen Buyens"

COPY . /app
WORKDIR /app

# install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# run securityheaders
ENTRYPOINT ["python", "securityheaders.py"]
