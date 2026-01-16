# Use Python as the base image
FROM python:3.10

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy the rest of your project files
COPY . .

# Command to run your app
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
