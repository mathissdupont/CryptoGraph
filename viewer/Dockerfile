FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir streamlit

COPY viewer.py /app/viewer.py

EXPOSE 8501

CMD ["streamlit", "run", "/app/viewer.py", "--server.address=0.0.0.0", "--server.port=8501"]
