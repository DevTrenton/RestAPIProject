FROM python:latest
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . . 
CMD ["gunicorn", "--bind", "0.0.0.0:80", "app:create_app()"]
