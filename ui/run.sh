#!/bin/bash

if [ "$SETUP_DB" == "yes" ]; then
  python3 manage.py init_db
fi

#uwsgi
uwsgi --ini start.ini

