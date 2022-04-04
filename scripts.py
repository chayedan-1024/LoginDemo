import json
import pickle
import base64
def set_login_config(username, password):
    login_info = {
        "login" : {
            "username" : username,
            "password" : password
        }
    }
    return base64.b64encode(pickle.dumps(login_info)).decode("utf-8")

def get_login_config(encoded_bytes):
    return pickle.loads(base64.b64decode(encoded_bytes.encode("utf-8")))

if __name__ == "__main__":
    encoded_info = set_login_config("root", "SHEN.1")
    with open("./Config/login.txt", "w") as f:
        f.write(encoded_info)