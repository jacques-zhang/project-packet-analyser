#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask import Flask, flash, render_template, send_file, make_response, url_for, Response, redirect, request, send_from_directory, safe_join, abort

import copy
from src import trace, dictionnaires, LesExceptions, traiteFichier, utils


app = Flask(__name__)
app.static_folder = 'static'
app.secret_key = 'mdr'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/', methods=["POST"])
def upload_file():
    f = request.files['txt_file']
    


    if f.filename == "":
        flash("Vous n'avez rien importé")
        return render_template("index.html")


    try:
        tr = trace.toListeTrame(f)
    except BaseException as err:
        flash("{0}".format(err))
        return render_template("index.html")

    res = trace.analyse(tr)
    """
    for i in range(len(res)):
        res[i] = res[i].replace("\t", "")
        res[i] = res[i].split("\n")
"""
    return render_template("index.html", content=res)



app.run(debug = True)