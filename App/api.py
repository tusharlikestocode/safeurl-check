from flask import Flask, jsonify, request
import json
import whois

app = Flask(__name__)
employees = [ { 'id': 1, 'name': 'Ashley' }, { 'id': 2, 'name': 'Kate' }, { 'id': 3, 'name': 'Joe' }]
url = [{'url': ''}]



@app.route('/url',methods=['GET'])
def hello():
    url = request.args.get('url')
    url_information = []
    information = {}
    # try:
    target_ip_address = url
    target_whois_info = whois.whois(target_ip_address)
    for key,value in target_whois_info.items():
        if key != "status":
            if isinstance(value, list):
                if 'date' in key:
                    information[key.capitalize()]=value[0]
                else:
                    information[key.capitalize()]=value
            else:
                if value is None:
                    information[key.capitalize()]="N/A"
                else:
                    information[key.capitalize()]=value
    # url_information.append(url_information)
    # return jsonify(url_information)
    # else:
    # whois_keys = ['name', 'emails', 'address', 'registrant_postal_code', 'registrar', 'creation_date', 'updated_date', 'expiration_date', 'country']
    # for key,value in target_whois_info.items():
    #     if key in whois_keys:
    #         if isinstance(value, list):
    #             if 'date' in key:
    #                 information[key.capitalize()]=value[0]
    #             else:
    #                 information[key.capitalize()]=value
    #         else:
    #             if value is None:
    #                 information[key.capitalize()]="N/A"
    #             else:
    #                 information[key.capitalize()]=value
    url_information.append(information)
    return jsonify(url_information)
    # except Exception:
    #         return "Unable to retrieve whois information!!"
        


if __name__ == '__main__':
   app.run(port=5000)