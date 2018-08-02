from flask_restful import Resource
from flask import request
from app.config import CLIENT_FOLDER
import os, zipfile, hashlib

class UpdateCtrl(Resource):
    def get(self, hash):
        path = 'static' + os.sep + 'client.zip'
        try:
            os.remove(path)
        except:
            None
        zip = zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED)
        for root, dirs, files in os.walk(CLIENT_FOLDER):
            for f in files:
                zip.write(os.path.join(root, f))
        zip.close()

        client = open(path).read()

        if hash == hashlib.md5(client).hexdigest():
            return {"err": "invalid request"}, 400
        else:
            return {"url": request.url_root + path}, 200

