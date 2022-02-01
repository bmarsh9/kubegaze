# install base
FROM ubuntu

# update the operating system:
RUN apt-get update && apt-get install -y apt-transport-https
RUN apt install -y python3-pip nano net-tools sudo

# copy the folder to the container:
ADD . /indexer

# Define working directory:
WORKDIR /indexer

# Install the requirements
RUN pip3 install -r /indexer/requirements.txt

# default command: run the web server
CMD ["python3","/indexer/app.py"]

