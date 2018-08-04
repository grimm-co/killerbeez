import json

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        try:
            ts = o.timestamp()
            return ts
        except AttributeError:
            pass

        return super(JSONEncoder, self).default(o)
