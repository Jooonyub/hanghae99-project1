from flask import Flask, render_template, request, jsonify, redirect, url_for
from pymongo import MongoClient


app = Flask(__name__)

client = MongoClient('52.79.235.255', 27017, username="dnsu7676@gmail.com", password="dnpalz1z1!")
db = client.dbsparta_plus_week3


@app.route('/')
def main():
    return render_template("index.html")

@app.route('/map')
def test_map():
    return render_template("prac_map.html")

@app.route('/matjip', methods=["GET"])
def get_matjip():
    # 맛집 목록을 반환하는 API
    matjip_list = list(db.matjips.find({}, {'_id': False}))
    # matjip_list 라는 키 값에 맛집 목록을 담아 클라이언트에게 반환합니다.
    return jsonify({'result': 'success', 'matjip_list': matjip_list})

if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)