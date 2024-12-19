#!/bin/sh

flask db migrate

exec gunicorn --bind 0.0.0.0:80 "app.app:app"