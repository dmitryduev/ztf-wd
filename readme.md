### ZTF finds White Dwarfs

_Loyally serving Shri and the community_

Clone the repo and cd to the directory:
```bash
git clone https://github.com/dmitryduev/ztf-wd.git
cd ztf-wd
```

Create file secrets.json with the Kowalski login credentials and admin user/password for the website:
```json
{
  "kowalski": {
    "user": "USER",
    "password": "PASSWORD"
  },
  "database": {
    "admin_username": "ADMIN",
    "admin_password": "PASSWORD"
  }
}
```

Run `docker-compose`:
```bash
docker-compose up --build -d
```

To tear everything down (i.e. stop and remove the containers), run:
```bash
docker-compose down
```

---

If you want to use `docker run` instead:

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

Build and launch the main container:
```bash
docker build -t ztf-wd:latest -f Dockerfile .
docker run --name ztf-wd -d --restart always -p 8000:4000 -v ztf-wd-volume:/alerts --link ztf-wd-mongo:mongo ztf-wd:latest
# test mode:
docker run -it --rm --name ztf-wd -p 8000:4000 -v ztf-wd-volume:/alerts --link ztf-wd-mongo:mongo ztf-wd:latest
```
