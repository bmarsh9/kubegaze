#### Help

##### Clean docker  
`docker system prune -a`  
`docker volume prune`

##### Build and push  
`docker build -t <hub-user>/<repo-name>[:<tag>]`  
`docker tag <existing-image> <hub-user>/<repo-name>[:<tag>]`  
`docker push <hub-user>/<repo-name>:<tag>`

##### Git  
`git branch <branch>`  
`git checkout <branch>`  


#### docker
docker-compose up -d postgres_db && sleep 10 && docker-compose up -d kubegaze_ui kubegaze_poller
