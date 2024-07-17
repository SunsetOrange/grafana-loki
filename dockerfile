FROM python:3.12.4-bookworm

WORKDIR /carnivorous-garden

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["python", "app.py"]
