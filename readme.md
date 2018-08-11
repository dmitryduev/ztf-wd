### ZTF finds White Dwarfs

_Loyally serving the community and Shri_

Clone the repo and cd to the directory:
```bash
git clone https://github.com/dmitryduev/ztf-wd.git
cd archiver-kped
```

Create a persistent Docker volume for MongoDB:
```bash
docker volume create ztf-wd-mongo-volume
```

Launch the MongoDB container. Feel free to change u/p for the admin
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

Bulid and launch the main container:
```bash
docker build -t ztf-wd -f Dockerfile .
docker run --name ztf-wd -d --link ztf-wd-mongo:mongo --restart always ztf-wd
```
