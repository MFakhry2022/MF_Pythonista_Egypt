# Use an official Python runtime as the base image
FROM python:3.11.5

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file to the container
COPY requirements.txt .

# Install the Python dependencies
RUN pip install -r requirements.txt

# Copy the project files to the container
COPY . .

# Expose the port your Django application will run on
EXPOSE 8000

# Define the command to start the Django development server
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]