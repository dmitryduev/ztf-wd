### ZTF finds White Dwarfs

_Loyally serving Shri and the community_

Clone the repo and cd to the directory:
```bash
git clone https://github.com/dmitryduev/ztf-wd.git
cd ztf-wd
```

Create a persistent Docker volume for MongoDB and to store thumbnails etc.:
```bash
docker volume create ztf-wd-mongo-volume
docker volume create ztf-wd-volume
```

Launch the MongoDB container. Feel free to change u/p for the admin, but make sure to change config.json correspondingly.
```bash
docker run -d --restart always --name ztf-wd-mongo -p 27018:27017 -v ztf-wd-mongo-volume:/data/db \
       -e MONGO_INITDB_ROOT_USERNAME=mongoadmin -e MONGO_INITDB_ROOT_PASSWORD=mongoadminsecret \
       mongo:latest
```

Create file secrets.json with the Kowalski login credentials:
```json
{
  "kowalski": {
    "user": "USER",
    "password": "PASSWORD"
  }
}
```

Build and launch the main container:
```bash
docker build -t ztf-wd -f Dockerfile .
docker run --name ztf-wd -d --restart always -p 8000:4000 -v ztf-wd-volume:/alerts --link ztf-wd-mongo:mongo ztf-wd
# test mode:
docker run -it --rm --name ztf-wd -p 8000:4000 -v ztf-wd-volume:/alerts --link ztf-wd-mongo:mongo ztf-wd
```
