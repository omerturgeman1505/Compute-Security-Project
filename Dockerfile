FROM python:3.10.10

# Set the working directory in the container to /app
WORKDIR /app
ADD . /app

RUN pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org --no-cache-dir -r requirements.txt

EXPOSE 5000
CMD ["python", "backend.py"]