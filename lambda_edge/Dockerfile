FROM public.ecr.aws/lambda/python:3.10

WORKDIR /asset

COPY requirements.txt .
RUN pip install -r requirements.txt -t .

COPY auth.py .

CMD ["echo", "Package created successfully"]