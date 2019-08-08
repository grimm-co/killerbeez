import os
# For feature testing, it's ok to use sqlite. SQLAlchemy will magic away the difference under the hood
DATABASE_URI = "sqlite:///../../../../moflow.db"
#DATABASE_URI = "postgresql://localhost/killerbeez?user=killerbeez&password=killerbeez"
MANAGER_VERSION = 0.1
CLIENT_FOLDER = "client"
UPLOAD_FOLDER = 'static' + os.sep + 'upload'
