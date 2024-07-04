FROM python:3.9.19-alpine3.20
RUN mkdir /app
COPY ./ip_address.py /app
COPY ./requirements.txt /app
WORKDIR /app
RUN pip install -r requirements.txt
CMD [ "python", "./ip_address.py" ]