# install base
FROM ubuntu

# update the operating system:
RUN apt-get update && apt-get install -y apt-transport-https
RUN apt install -y python3-pip nano net-tools sudo

# copy the folder to the container:
ADD . /poller

# Define working directory:
WORKDIR /poller

# Install the requirements
RUN pip3 install -r /poller/requirements.txt

# default command: run the web server
CMD ["python3","/poller/app.py"]

