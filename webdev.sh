#!/bin/bash

fastapi dev saci/webui/web.py &

cd web
npm run dev
